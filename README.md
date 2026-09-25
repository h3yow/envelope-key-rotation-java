# Envelope Key Rotation (Java / Spring Boot)

在 Spring Boot 服务内实现的本地信封加密与密钥轮换能力。密钥生命周期完全由进程内状态模拟，
不同密钥版本下的加解密结论与失败原因可预期、可复现。

## 构建与验证

```bash
mvn test          # 运行全部 19 个测试（含并发轮换、历史兼容、篡改、生命周期）
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

## REST API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/keys/encrypt` | `{"plaintext": "..."}` → `{"ciphertext", "keyVersion"}` |
| POST | `/api/keys/decrypt` | `{"ciphertext": "..."}` → `{"plaintext", "keyVersion"}` |
| POST | `/api/keys/rotate` | 轮换 → `{"activeVersion"}` |
| POST | `/api/keys/{version}/deactivate` | 停用指定版本 |
| POST | `/api/keys/{version}/destroy` | 销毁指定版本（须先停用） |
| GET | `/api/keys` | 列出版本与状态（不含密钥材料） |

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

单测日志会打印密钥版本与判定依据（`assertion basis: expectedReason=..., actualReason=..., keyVersion=...`），
可用 `mvn test | grep "assertion basis"` 观察。
