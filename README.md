# Envelope Key Rotation (Local Simulation)

A Spring Boot service implementing local envelope encryption with versioned
keys and a full key lifecycle (rotate / disable / destroy), simulated entirely
with in-process state so that outcomes and failure reasons are deterministic
and reproducible.

## Envelope Format

Ciphertext is Base64url(no padding) of:

```
magic "EK" (2 bytes) | version (4 bytes, big-endian) | IV (12 bytes) | AES-256-GCM ciphertext || tag (16 bytes)
```

- The version header travels with every ciphertext, so decryption always knows
  exactly which key version to use.
- `magic || version` is bound into the GCM AAD: rewriting the version header
  fails the integrity check. There is **no fallback** to any other key.

## Version Compatibility Strategy

- New encryptions always use the current `ACTIVE` key version.
- Historical ciphertexts remain decryptable as long as their key version is
  `ACTIVE` or `DISABLED`.
- Decryption never substitutes another key: unknown versions are rejected with
  `UNKNOWN_KEY_VERSION`, forged version headers with `INTEGRITY_CHECK_FAILED`.

## Rotation Semantics

- `rotate()` unconditionally installs a fresh `ACTIVE` version; old versions
  keep their status and remain decryptable.
- `rotate(expectedVersion)` uses compare-and-set semantics: the rotation only
  happens if the active version still equals `expectedVersion`. Concurrent
  rotation requests therefore **converge to exactly one rotation** — one caller
  reports `rotated=true`, all others observe the same resulting active version
  with `rotated=false`. All mutations are serialized on the `KeyManager`
  monitor, so no partial rotation or divergent read/write view is possible.

## Lifecycle Semantics (irreversible)

| State      | Encrypt | Decrypt | Allowed transitions        |
|------------|---------|---------|----------------------------|
| `ACTIVE`   | yes     | yes     | → `DISABLED`, → `DESTROYED` |
| `DISABLED` | no (`KEY_DISABLED` if it is the active key) | yes | → `DESTROYED` |
| `DESTROYED`| no (`KEY_DESTROYED`) | no (`KEY_DESTROYED`) | none |

- `disable`: decrypt-only; repeated disable → `ILLEGAL_STATE_TRANSITION`.
- `destroy`: key material is zeroed and dropped; repeated destroy or
  disable-after-destroy → `ILLEGAL_STATE_TRANSITION`.
- Operations on nonexistent versions → `UNKNOWN_KEY_VERSION`.

## Error Classification

All failures raise `CryptoException` with a `CryptoErrorCode`, mapped to HTTP
by `CryptoExceptionHandler`:

| Code                     | HTTP | Meaning |
|--------------------------|------|---------|
| `MALFORMED_CIPHERTEXT`   | 400  | Not Base64url / bad magic / truncated |
| `VERSION_MISSING`        | 400  | Envelope carries no usable version header |
| `INVALID_ARGUMENT`       | 400  | Null plaintext etc. |
| `UNKNOWN_KEY_VERSION`    | 404  | Referenced key version not held |
| `INTEGRITY_CHECK_FAILED` | 409  | AEAD tag mismatch (tampering, forged version) |
| `KEY_DISABLED`           | 409  | Operation needs an ACTIVE key but it is DISABLED |
| `KEY_DESTROYED`          | 409  | Key material erased |
| `ILLEGAL_STATE_TRANSITION` | 409 | Lifecycle transition not permitted |
| `NO_ACTIVE_KEY`          | 409  | No key available for encryption |

Key material, plaintext, and derived secrets never appear in logs, exception
messages, or API responses — only versions, statuses, and error codes.

## REST API

```
POST /api/encrypt            {"plaintext": "..."}        -> {"ciphertext": "...", "version": n}
POST /api/decrypt            {"ciphertext": "..."}       -> {"plaintext": "...", "version": n}
POST /api/keys/rotate        {"expectedVersion": n}?     -> {"activeVersion": n, "rotated": bool}
POST /api/keys/{v}/disable
POST /api/keys/{v}/destroy
GET  /api/keys                                       -> [{"version": n, "status": "..."}]
```

Errors: `{"code": "...", "message": "..."}` with the HTTP status above.

## Verification

```
mvn test
```

`CryptoServiceTest` covers and logs (key versions + assertion basis):

- encrypt/decrypt roundtrip with version carriage
- historical ciphertext decryptable after rotation
- 16-thread concurrent rotation converging to one result (`rotatedCount=1`,
  single new version, all callers agree)
- bit-flip tampering → `INTEGRITY_CHECK_FAILED`
- forged version header → `INTEGRITY_CHECK_FAILED` (AAD binding, no fallback)
- malformed / missing-version / unknown-version ciphertexts → distinct codes
- disable/destroy semantics, irreversibility, and illegal transitions
- stale-expectation rotation converging without a second rotation
