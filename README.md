# Envelope Key Rotation (Java / Spring Boot)

在 Spring Boot 服务内实现的本地信封加密与密钥轮换能力。密钥生命周期完全由进程内状态模拟，
不同密钥版本下的加解密结论与失败原因可预期、可复现。

## 构建与验证

```bash
mvn test          # 运行全部 27 个测试（含并发轮换、批量迁移、历史兼容、篡改、生命周期、版本边界）
mvn spring-boot:run
```

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

## 密钥生命周期语义

```
ACTIVE --(rotate)--> DECRYPT_ONLY --(deactivate)--> DISABLED --(destroy)--> DESTROYED
ACTIVE --(deactivate)--> DISABLED
```

| 状态 | 加密 | 解密 | 说明 |
|---|---|---|---|
| ACTIVE | ✅ | ✅ | 全局唯一，轮换产生 |
| DECRYPT_ONLY | ❌ | ✅ | 被轮换取代，兼容历史密文 |
| DISABLED | ❌ | ❌ | 材料保留，可销毁；拒绝原因 `KEY_DISABLED` |
| DESTROYED | ❌ | ❌ | 材料已清零，不可逆；拒绝原因 `KEY_DESTROYED` |

- **轮换**：生成新版本并设为活跃，旧活跃版本自动降级为 DECRYPT_ONLY。
  并发轮换通过“纪元（epoch）检查 + 临界区”收敛：进入临界区前记录轮换纪元，
  若等待期间已有其他线程完成轮换，则直接采纳其结果——重叠的轮换请求收敛为唯一结果，
  恰好产生一个新版本，不会出现多个活跃版本或部分轮换；轮换期间读写结论一致。
- **停用**：ACTIVE/DECRYPT_ONLY → DISABLED。停用活跃版本后加密返回 `NO_ACTIVE_KEY`，
  需轮换出新版本方可恢复加密。
- **销毁**：仅允许从 DISABLED 迁移，密钥材料清零，不可逆。
  ACTIVE 直接销毁等非法迁移以 `ILLEGAL_STATE_TRANSITION` 拒绝。
  若已配置密文存储且其中仍有密文引用该版本，销毁以 `KEY_IN_USE` 拒绝
  （引用检查优先于状态迁移检查，原因可与其他失败明确区分）——
  即一个版本只有在确认没有任何密文引用后才允许销毁。

## 批量迁移（旧数据重加密到最新版本）

`MigrationService` 把密文存储中的旧版本密文统一重加密到当前活跃版本，
迁移前后解出的明文完全一致。典型用法：

```java
MigrationReport report = migrationService.migrateAll();        // 全量
MigrationReport partial = migrationService.migrateBatch(ids);  // 指定一批
// report: total / migrated / alreadyCurrent / failed / failures(含可区分原因)
```

REST：`POST /api/keys/migrate` 迁移存储中的全部记录，返回同上报告。

语义约定：

- **幂等**：已在当前活跃版本的记录原样跳过（计入 `alreadyCurrent`），
  同一批数据重复执行第二遍、第三遍不产生重复结果（`migrated=0`），
  密文字节完全不变，已迁移数据不会被破坏。
- **可续跑**：逐条处理、逐条经 CAS 写回即生效。中途中断后重新执行同一批请求即可
  从断点继续——已处理部分被识别为 `alreadyCurrent`，不会被重新处理，也不会回退
  （迁移只写入当前活跃版本，绝不写回旧版本）。
- **并发收敛**：写回采用 compare-and-set，仅当存储值仍等于迁移前读到的值才生效；
  多个迁移者同时处理同一批数据时，每条记录恰好被一个迁移者重加密，
  其余迁移者重读后识别为已完成，最终收敛为同一结果，不会出现两套并行的迁移方向。
- **不停服**：迁移期间读写照常。未迁移的记录按旧版本解密、已迁移的按新版本解密，
  任意时刻读出的明文一致；新写入直接使用当前活跃版本。
- **单条失败不阻断**：解密失败等原因计入 `failures`（含记录 id 与 `FailureReason`），
  其余记录继续处理。

## 版本保留上限与销毁边界

- **保留上限**：`KeyManager` 构造时可指定 `maxVersions`（默认 64）。
  版本数达到上限后，新的**轮换**与**迁移**请求都以 `VERSION_LIMIT_EXCEEDED`
  明确拒绝——绝不悄悄淘汰最老版本或让版本凭空消失；拒绝不影响已有密文的解密。
- **销毁边界**：`destroy` 前检查密文存储，只要还有密文引用该版本即以
  `KEY_IN_USE` 拒绝（且不清除密钥材料）；确认零引用后才允许销毁。
  推荐下线顺序：`rotate` → `migrate`（确认无引用）→ `deactivate` → `destroy`。
  注意：版本停用（DISABLED）后其密文即不可解密，迁移必须在停用前完成。

## 错误分类

所有失败抛出 `KeyOperationException`，携带 `FailureReason`；REST 层映射为 HTTP 响应
（响应体只含 `reason`/`message`/`keyVersion`，不含明文、密文或密钥材料）：

| FailureReason | HTTP | 触发条件 |
|---|---|---|
| VERSION_MISSING | 400 | 密文未携带版本或版本非法 |
| CIPHERTEXT_MALFORMED | 400 | 密文结构/编码无法解析 |
| CIPHERTEXT_TAMPERED | 409 | GCM 完整性校验失败（篡改、版本字段被替换） |
| KEY_NOT_FOUND | 404 | 密文引用的版本不存在 |
| KEY_DISABLED | 409 | 密钥已停用 |
| KEY_DESTROYED | 409 | 密钥已销毁 |
| NO_ACTIVE_KEY | 409 | 无可用活跃版本（活跃键被停用） |
| ILLEGAL_STATE_TRANSITION | 409 | 非法生命周期迁移 |
| KEY_IN_USE | 409 | 版本仍被密文引用，拒绝销毁 |
| VERSION_LIMIT_EXCEEDED | 507 | 保留版本数达上限，拒绝轮换/迁移 |

## REST API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/keys/encrypt` | `{"plaintext": "..."}` → `{"ciphertext", "keyVersion"}` |
| POST | `/api/keys/decrypt` | `{"ciphertext": "..."}` → `{"plaintext", "keyVersion"}` |
| POST | `/api/keys/rotate` | 轮换 → `{"activeVersion"}` |
| POST | `/api/keys/migrate` | 批量迁移全部记录到当前版本 → `{"total","migrated","alreadyCurrent","failed","failures"}` |
| POST | `/api/keys/{version}/deactivate` | 停用指定版本 |
| POST | `/api/keys/{version}/destroy` | 销毁指定版本（须先停用且无引用） |
| GET | `/api/keys` | 列出版本与状态（不含密钥材料） |
| PUT | `/api/records/{id}` | `{"plaintext": "..."}` 加密写入一条业务记录（模拟在线写流量） |
| GET | `/api/records/{id}` | 读取并解密一条记录（迁移前后明文一致） |
| GET | `/api/records` | 列出记录 id 与密文版本（不暴露密文） |

## 测试与验证方法

| 测试 | 覆盖点 |
|---|---|
| `KeyManagerConcurrencyTest.overlappingRotationsConvergeToUniqueResult` | 用测试钩子确定性构造真实重叠的轮换，断言收敛为唯一结果、恰好一个新版本、唯一活跃版本 |
| `KeyManagerTest.burstRotationKeepsStateConsistent` | 16 线程突发轮换：状态一致、无部分轮换、版本连续 |
| `KeyManagerTest.concurrentEncryptDecryptDuringRotationIsConsistent` | 轮换期间并发读写结论一致 |
| `KeyManagerTest.historyCiphertextStillDecryptsAfterRotation` | 历史密文兼容、新加密使用最新版本 |
| `KeyManagerTest.tamperedPayloadRejected` / `tamperedVersionFieldRejected` | 密文篡改、版本字段替换均被拒绝且不回退 |
| `KeyManagerTest.disabledKeyRejectsEncryptAndDecrypt` / `destroyIsIrreversibleAndClearsMaterial` | 停用/销毁语义、不可逆性、材料清零 |
| `KeyManagerTest.keyMaterialNeverLeaksIntoExceptionOrToString` | 密钥材料不泄露 |
| `KeyControllerTest` | HTTP 层错误分类与响应脱敏 |
| `MigrationServiceTest.batchMigrationReencryptsToLatestAndPlaintextIdentical` | 批量迁移到最新版本，迁移前后明文一致 |
| `MigrationServiceTest.migrationIsIdempotentAcrossRepeatedRuns` | 幂等：重复执行不产生重复结果，密文稳定不变 |
| `MigrationServiceTest.interruptedMigrationResumesWithoutReprocessing` | 中断续跑：已处理部分不重处理、不回退 |
| `MigrationServiceTest.concurrentMigratorsConvergeToSameResult` | 多迁移者并发收敛：每条记录恰好迁移一次 |
| `MigrationServiceTest.migrationDuringConcurrentReadWriteIsConsistent` | 迁移与在线读写并存时结论一致 |
| `MigrationServiceTest.destroyRejectedWhileVersionStillReferenced` | 版本被引用时销毁以 `KEY_IN_USE` 拒绝，迁移完成后才允许销毁 |
| `MigrationServiceTest.versionLimitRejectsRotationAndMigration` | 版本数达上限时轮换与迁移均以 `VERSION_LIMIT_EXCEEDED` 拒绝，无静默淘汰 |
| `MigrationServiceTest.reencryptOnCurrentVersionCiphertextIsPassThrough` | 当前版本密文重加密为 no-op |

单测日志会打印密钥版本与判定依据（`assertion basis: expectedReason=..., actualReason=..., keyVersion=...`），
可用 `mvn test | grep "assertion basis"` 观察；迁移场景用例打印 `scenario=<场景名>: ... PASS`，
可用 `mvn test | grep "scenario="` 查看每个迁移场景的用例与结果。

本地手动验证迁移（无需外部服务）：

```bash
mvn spring-boot:run &
curl -X PUT localhost:8080/api/records/a -H 'Content-Type: application/json' -d '{"plaintext":"old-data"}'
curl -X POST localhost:8080/api/keys/rotate     # 轮换出新版本
curl -X POST localhost:8080/api/keys/migrate    # {"total":1,"migrated":1,"alreadyCurrent":0,...}
curl -X POST localhost:8080/api/keys/migrate    # 幂等：{"migrated":0,"alreadyCurrent":1,...}
curl localhost:8080/api/records/a               # 明文仍为 old-data
```
