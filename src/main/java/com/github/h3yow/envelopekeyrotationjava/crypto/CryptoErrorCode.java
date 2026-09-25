package com.github.h3yow.envelopekeyrotationjava.crypto;

/**
 * Machine-distinguishable failure reasons for crypto and lifecycle operations.
 * Codes are safe to expose; they never carry key material.
 */
public enum CryptoErrorCode {
    /** Ciphertext cannot be parsed (bad encoding, truncated, unsupported format). */
    MALFORMED_CIPHERTEXT,
    /** Ciphertext parses but carries no key-version header. */
    VERSION_MISSING,
    /** Ciphertext references a key version this process does not hold. */
    UNKNOWN_KEY_VERSION,
    /** Operation requires an ACTIVE key but the key is DISABLED. */
    KEY_DISABLED,
    /** Operation requires key material but the key is DESTROYED. */
    KEY_DESTROYED,
    /** Authenticated-decryption failed: ciphertext was tampered with. */
    INTEGRITY_CHECK_FAILED,
    /** Lifecycle transition is not permitted from the current state. */
    ILLEGAL_STATE_TRANSITION,
    /** No ACTIVE key exists, so encryption cannot be performed. */
    NO_ACTIVE_KEY,
    /** Caller supplied an invalid argument. */
    INVALID_ARGUMENT
}
