# Envelope Key Rotation (Java / Spring Boot)

在 Spring Boot 服务内实现的本地信封加密、密钥轮换与**存量数据批量迁移**能力。
密钥生命周期与"老数据"存储都由进程内状态模拟，不同版本下的加解密结论、失败原因、
迁移进度与版本下线边界均可预期、可复现，不依赖任何外部服务。

## 构建与验证

```bash
mvn test          # 运行全部 45 个测试
mvn spring-boot:run
```

- `mvn test | grep 场景`：查看新增的迁移/治理用例都覆盖了哪些场景与结果；
- `mvn test | grep "assertion basis"`：查看失败原因断言（期望原因 vs 实际原因 vs 版本）。

## 加密方案

- 每个密钥版本持有一个随机 AES-256 KEK（密钥加密密钥），仅存在于进程内存。
- 每条消息生成随机 DEK（数据加密密钥）：
  - DEK 由 KEK 以 AES-GCM 包裹（wrap）；
  - 明文由 DEK 以 AES-GCM 加密；
  - 两段 GCM 的 AAD 均绑定密钥版本号，篡改密文中的版本字段会导致认证失败。
- DEK 使用后立即清零；密钥材料不出现在日志、异常信息或任何对外响应中。

密文线性格式（自描述，携带版本信息）：

```
EK1.<version>.<base64url(payload)>
payload = wrapIv(12B) | wrappedDek(48B) | dataIv(12B) | dataCiphertext+tag
```

## 版本兼容策略

- **加密**始终使用当前唯一活跃（ACTIVE）版本。
- **解密**严格按密文携带的版本寻址对应密钥，**绝不回退**到其他版本；
  版本缺失、密钥不存在、密钥已停用/已销毁分别给出可区分的失败原因。
- 轮换后历史密文仍可解密（旧版本降级为 DECRYPT_ONLY，仅解密、不再加密）。
- 任意时刻至多一个 ACTIVE 版本（由单测断言保证）。

## 存量数据批量迁移

`BatchMigrationService` 把一批旧版本密文统一重加密为**当前加密版本**。
存储层 `CiphertextStore` 模拟业务库：每条记录保存自描述密文，并按版本维护引用计数。

### 怎么用（REST）

```bash
# 1) 写入一批老数据（用当时的活跃版本加密）
curl -s -XPOST localhost:8080/api/records -H 'Content-Type: application/json' \
  -d '{"id":"rec-1","plaintext":"alice"}'

# 2) 轮换密钥：老数据仍停留在旧版本，但读取依旧正确
curl -s -XPOST localhost:8080/api/keys/rotate

# 3) 批量迁移（不传 ids 即全量；maxBatch 控制每片条数）
curl -s -XPOST localhost:8080/api/migrations -H 'Content-Type: application/json' \
  -d '{"maxBatch":100}'
# {"targetVersion":2,"processed":1,"skipped":0,"failed":0,"totalCandidates":1,
#  "hasMore":false,"nextCursor":null,"failures":[]}

# 4) 读取：明文不变，keyVersion 已变为最新版本
curl -s localhost:8080/api/records/rec-1
```

Java 侧等价入口：

```java
MigrationResult r = migrationService.migrateBatch(ids, 100, cursor);
// 或一把梭（小数据量）：
migrationService.migrateAll(ids);
```

### 语义约定

| 语义 | 保证 |
|---|---|
| **正确性** | 先按旧版本解密、再用当前活跃版本重加密；迁移前后明文逐字节一致（单测全量比对）。 |
| **原子替换** | 记录级"比较旧密文再替换"（CAS），与引用计数调整在同一临界区完成。读永远看到一份**完整旧密文或完整新密文**，不会读到半截；密文自描述版本与记录版本始终一致。 |
| **幂等** | 已处于目标版本的记录直接跳过；重复执行第二遍、第三遍 `processed=0`、`skipped=N`，已迁好的密文一个字节都不改写、不回退。 |
| **可续跑** | 响应中的 `nextCursor` 编码"目标版本 + 下一起点"。中断后带游标继续：`hasMore=false` 前每次只处理下一片，已处理部分不重做。即使游标丢失，无游标全量重跑同样安全（已迁的跳过、未迁的补齐）。 |
| **单条失败不拖垮整批** | 某条旧密文解不开（源版本被停用/销毁、密文损坏）时计入 `failures[].reason`，其余记录照常迁移。 |
| **并发收敛（单飞）** | 同一时刻只有一个迁移真正执行；多人同时发起迁移，目标版本统一为同一个，每条记录恰好被重加密一次，不会出现两套并行迁移方向。 |
| **游标绑定目标版本** | 游标只允许续跑到它所属的目标版本；若期间又轮换过，拿旧游标续跑会以 `ILLEGAL_STATE_TRANSITION` 被拒，需要无游标开启朝新版本的迁移（已迁记录自动跳过）。 |
| **与在线读写并存** | 迁移期间服务不停：新写入始终走当前活跃版本；与迁移交错的覆盖写由 CAS 决出唯一结果，任何时刻读取都能正确解密且版本结论自洽。 |

迁移结果字段：

| 字段 | 含义 |
|---|---|
| `targetVersion` | 本次迁移固定写入的版本（任务开始时锁定） |
| `processed` / `skipped` / `failed` | 本片实际重加密 / 幂等跳过 / 失败的条数 |
| `totalCandidates` | 本次扫描到的候选记录总数 |
| `hasMore` / `nextCursor` | 是否还有未处理记录 / 续跑游标（完成时为 null） |
| `failures[]` | `{id, reason, message}`，只含诊断信息，不含明文或密文内容 |

## 版本下线边界与保留上限

```
ACTIVE --(rotate)--> DECRYPT_ONLY --(deactivate)--> DISABLED --(destroy)--> DESTROYED
ACTIVE --(deactivate)--> DISABLED
```

| 状态 | 加密 | 解密 | 说明 |
|---|---|---|---|
| ACTIVE | ✅ | ✅ | 全局唯一，轮换产生 |
| DECRYPT_ONLY | ❌ | ✅ | 被轮换取代，兼容历史密文，**迁移期间必须保持此状态** |
| DISABLED | ❌ | ❌ | 材料保留，可销毁；拒绝原因 `KEY_DISABLED` |
| DESTROYED | ❌ | ❌ | 材料已清零，不可逆；拒绝原因 `KEY_DESTROYED` |

### 销毁边界：没有密文引用才能销毁

存储层按版本维护引用计数。销毁时**先做引用检查、再做状态迁移**：

- 只要还有任何记录引用该版本，无论它处于 ACTIVE / DECRYPT_ONLY / DISABLED，
  一律以 **`KEY_STILL_REFERENCED`（HTTP 409）** 拒绝，且不会留下半销毁状态；
- 引用清零后，走 `deactivate` → `destroy` 才成功，密钥材料清零、不可逆；
- 标准下线顺序：**先迁移搬空引用 → 再停用 → 再销毁**。
  在旧版本还 DECRYPT_ONLY 时迁移才能解密老密文；提前停用会让对应记录迁移失败（进入 `failures`）。
- 并发场景：迁移进行中反复点销毁，得到的只会是 `KEY_STILL_REFERENCED`；
  迁移完成、引用归零的那一刻起，停用+销毁立即成功（有并发测试覆盖）。

### 保留上限：到容量了明确拒绝，绝不静默丢版本

- 上限由 `crypto.max-versions` 配置（默认 10，进程内构造器也可显式指定）。
- 保留版本（未销毁）数量 **达到** 上限时：
  - **轮换**以 `VERSION_LIMIT_EXCEEDED`（HTTP 409）被拒绝，最老版本**不会**被悄悄丢弃；
  - **迁移仍允许**：迁移不新增版本，而且它是把数据搬离旧版本、让旧版本可销毁、
    从而释放名额的唯一出路。
- 当保留数**超过**上限（例如运维把上限从 10 下调到 3、而库里已有 4 个保留版本）时：
  轮换与迁移都被明确拒绝；已有版本一个不少。必须先销毁无引用的旧版本，
  让保留数回落到新上限以内，迁移才恢复。
- 已销毁的版本不再占用保留名额。

## 错误分类

所有失败抛出 `KeyOperationException`，携带 `FailureReason`；REST 层映射为 HTTP 响应
（响应体只含 `reason`/`message`/`keyVersion`，不含明文、密文或密钥材料）：

| FailureReason | HTTP | 触发条件 |
|---|---|---|
| VERSION_MISSING | 400 | 密文未携带版本或版本非法 |
| CIPHERTEXT_MALFORMED | 400 | 密文结构/编码无法解析（含非法迁移游标、非法 maxBatch） |
| CIPHERTEXT_TAMPERED | 409 | GCM 完整性校验失败（篡改、版本字段被替换） |
| KEY_NOT_FOUND | 404 | 密文引用的版本不存在 / 记录不存在 |
| KEY_DISABLED | 409 | 密钥已停用 |
| KEY_DESTROYED | 409 | 密钥已销毁 |
| NO_ACTIVE_KEY | 409 | 无可用活跃版本（活跃键被停用，无法加密/迁移） |
| ILLEGAL_STATE_TRANSITION | 409 | 非法生命周期迁移；或拿绑定旧目标版本的游标续跑 |
| **KEY_STILL_REFERENCED** | 409 | **版本仍被存量密文引用，拒绝销毁** |
| **VERSION_LIMIT_EXCEEDED** | 409 | **保留版本数达到/超过上限，拒绝轮换（超限时连迁移也拒绝）** |

## REST API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/keys/encrypt` | `{"plaintext": "..."}` → `{"ciphertext", "keyVersion"}` |
| POST | `/api/keys/decrypt` | `{"ciphertext": "..."}` → `{"plaintext", "keyVersion"}` |
| POST | `/api/keys/rotate` | 轮换 → `{"activeVersion"}`；满员时 409 `VERSION_LIMIT_EXCEEDED` |
| POST | `/api/keys/{version}/deactivate` | 停用指定版本 |
| POST | `/api/keys/{version}/destroy` | 销毁指定版本（须先停用且无密文引用） |
| GET  | `/api/keys` | 列出版本与状态（不含密钥材料） |
| POST | `/api/records` | `{"id","plaintext"}` 以当前活跃版本加密并保存记录 |
| GET  | `/api/records/{id}` | 读取并解密记录 → `{"id","plaintext","keyVersion"}` |
| GET  | `/api/records` | 列出全部记录（密文+版本，不含密钥材料） |
| POST | `/api/migrations` | `{"ids"?,"maxBatch"?,"cursor"?}` → `MigrationResult` |

## 本地验证（典型剧本）

```bash
mvn spring-boot:run
# 另开终端（随机端口见启动日志，可把 server.port 改成 8080）：
BASE=http://localhost:8080

# 造 5 条 v1 老数据
for i in 1 2 3 4 5; do
  curl -s -XPOST $BASE/api/records -H 'Content-Type: application/json' \
    -d "{\"id\":\"rec-$i\",\"plaintext\":\"secret-$i\"}" >/dev/null
done
curl -s -XPOST $BASE/api/keys/rotate            # -> v2，老数据仍在 v1

# 分两片迁移（每片 2 条），观察 processed / hasMore / nextCursor
curl -s -XPOST $BASE/api/migrations -H 'Content-Type: application/json' \
  -d '{"maxBatch":2}'                            # processed=2, hasMore=true
# 把上一次响应里的 nextCursor 贴进来续跑：
curl -s -XPOST $BASE/api/migrations -H 'Content-Type: application/json' \
  -d '{"maxBatch":2,"cursor":"<nextCursor>"}'
# ... 直到 hasMore=false；再跑一遍必然 processed=0、skipped=5（幂等）

# 迁移完成前销毁 v1 -> 409 KEY_STILL_REFERENCED；迁移完成后：
curl -s -XPOST $BASE/api/keys/1/deactivate
curl -s -XPOST $BASE/api/keys/1/destroy          # 引用已清零，成功
curl -s $BASE/api/records/rec-1                  # 明文仍是 secret-1，版本为 v2
```

## 测试与验证方法

全部 45 个测试均为本地单测，`mvn test` 一键复现。新增用例：

| 测试 | 覆盖点 |
|---|---|
| `CiphertextStoreTest`（3） | 记录存取、按版本的引用计数、CAS 原子替换的幂等与不回退 |
| `BatchMigrationServiceTest`（9） | 迁移后明文一致；重复执行幂等；游标中断续跑（10+10+5）；游标丢失后无游标全量恢复；id 子集；单条失败收集不中断；无活跃键拒绝；跨目标版本游标拒绝；批次中途轮换时本批次安全失败、重跑朝新版本收敛 |
| `MigrationConcurrencyTest`（3） | 8 人同时迁移收敛为同一结果（每条恰好重加密一次）；迁移与在线新增/覆盖写、持续读并存时零错误、最终无旧版本残留；迁移与销毁并发时只可能得到 KEY_STILL_REFERENCED、引用清零后销毁成功 |
| `KeyGovernanceTest`（5） | 被引用版本在 ACTIVE/DECRYPT_ONLY/DISABLED 下销毁都被拒且原因可区分；引用清零后销毁成功；到上限轮换被拒且不丢版本；销毁旧版本释放名额后轮换恢复 |
| `MigrationCapacityTest`（3） | 保留数=上限时轮换拒绝但迁移放行；上限下调导致超限时迁移也被拒、销毁无引用版本后回落恢复 |
| `MigrationApiTest`（3） | HTTP 端到端：保存/轮换/迁移/读取、幂等、3+3+1 分片续跑、引用拒绝销毁（响应脱敏） |

上一轮既有用例（`KeyManagerTest` 12 个、`KeyManagerConcurrencyTest` 2 个、
`KeyControllerTest` 4 个、`ApplicationTests` 1 个，共 19 个）保持原语义并全部通过；
唯一改动是大轮换量的并发用例显式使用更宽松的保留上限，以与新增的容量守卫解耦。
本轮新增 26 个用例（存储 3 + 迁移 9 + 迁移并发 3 + 治理 5 + 容量 3 + HTTP 3）。
