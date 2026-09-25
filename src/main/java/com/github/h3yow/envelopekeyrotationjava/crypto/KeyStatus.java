package com.github.h3yow.envelopekeyrotationjava.crypto;

/**
 * Lifecycle state of a key version. Transitions are irreversible:
 * ACTIVE -&gt; DISABLED -&gt; DESTROYED (ACTIVE -&gt; DESTROYED is also allowed).
 */
public enum KeyStatus {
    /** Usable for both encryption and decryption. */
    ACTIVE,
    /** Decrypt-only: no new encryptions, historical ciphertext still decryptable. */
    DISABLED,
    /** Key material erased: neither encryption nor decryption possible. */
    DESTROYED
}
