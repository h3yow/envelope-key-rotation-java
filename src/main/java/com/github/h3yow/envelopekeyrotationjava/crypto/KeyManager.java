package com.github.h3yow.envelopekeyrotationjava.crypto;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-process key store simulating a key lifecycle.
 *
 * <p>All mutating operations are serialized on this instance, so a rotation is
 * atomic: observers see either the old or the new active version, never a
 * partial state. {@link #rotate(int)} uses compare-and-set semantics on the
 * expected active version, so concurrent rotation requests converge to exactly
 * one rotation and one resulting active version.</p>
 *
 * <p>Lifecycle transitions are irreversible: ACTIVE -&gt; DISABLED -&gt;
 * DESTROYED. DISABLED keys remain usable for decryption only; DESTROYED keys
 * have their material erased and cannot decrypt.</p>
 */
public class KeyManager {

    private static final int KEY_BYTES = 32; // AES-256

    private final Map<Integer, KeyVersion> keys = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private volatile int activeVersion;

    /** Snapshot of one key version for read-only inspection (no key material). */
    public record KeyInfo(int version, KeyStatus status) {
    }

    /**
     * Result of a rotation attempt.
     *
     * @param activeVersion the version that is active after the call
     * @param rotated       true if this call installed a new version
     */
    public record RotationResult(int activeVersion, boolean rotated) {
    }

    public KeyManager() {
        installNewVersion();
    }

    /**
     * Rotates only if the current active version still equals
     * {@code expectedVersion}. Concurrent callers holding the same expectation
     * converge: exactly one rotates, the others observe the already-rotated
     * state and report {@code rotated=false} with the same resulting version.
     */
    public synchronized RotationResult rotate(int expectedVersion) {
        if (activeVersion != expectedVersion) {
            return new RotationResult(activeVersion, false);
        }
        return new RotationResult(installNewVersion(), true);
    }

    /** Unconditional rotation: always installs a fresh active version. */
    public synchronized RotationResult rotate() {
        return new RotationResult(installNewVersion(), true);
    }

    /**
     * Disables a key (decrypt-only). Irreversible. Disabling the active key
     * leaves the store without an encryption-capable key until the next
     * rotation.
     */
    public synchronized void disable(int version) {
        KeyVersion key = requireExisting(version);
        if (key.getStatus() != KeyStatus.ACTIVE) {
            throw new CryptoException(CryptoErrorCode.ILLEGAL_STATE_TRANSITION,
                    "cannot disable key version " + version + " in state " + key.getStatus());
        }
        key.setStatus(KeyStatus.DISABLED);
    }

    /**
     * Destroys a key: erases its material and marks it DESTROYED. Irreversible;
     * subsequent decrypts fail with KEY_DESTROYED.
     */
    public synchronized void destroy(int version) {
        KeyVersion key = requireExisting(version);
        if (key.getStatus() == KeyStatus.DESTROYED) {
            throw new CryptoException(CryptoErrorCode.ILLEGAL_STATE_TRANSITION,
                    "key version " + version + " is already destroyed");
        }
        byte[] material = key.getMaterial();
        if (material != null) {
            Arrays.fill(material, (byte) 0);
        }
        key.eraseMaterial();
        key.setStatus(KeyStatus.DESTROYED);
    }

    /**
     * Returns the ACTIVE key for encryption. Failure reason distinguishes a
     * DISABLED active key, a DESTROYED active key, and no key at all.
     */
    KeyVersion requireActiveForEncrypt() {
        KeyVersion key = keys.get(activeVersion);
        if (key == null) {
            throw new CryptoException(CryptoErrorCode.NO_ACTIVE_KEY,
                    "no ACTIVE key available for encryption");
        }
        return switch (key.getStatus()) {
            case ACTIVE -> key;
            case DISABLED -> throw new CryptoException(CryptoErrorCode.KEY_DISABLED,
                    "active key version " + key.getVersion() + " is disabled; rotate before encrypting");
            case DESTROYED -> throw new CryptoException(CryptoErrorCode.KEY_DESTROYED,
                    "active key version " + key.getVersion() + " has been destroyed; rotate before encrypting");
        };
    }

    /** Returns the key for decryption, enforcing lifecycle rules. */
    KeyVersion requireForDecrypt(int version) {
        KeyVersion key = keys.get(version);
        if (key == null) {
            throw new CryptoException(CryptoErrorCode.UNKNOWN_KEY_VERSION,
                    "unknown key version " + version);
        }
        if (key.getStatus() == KeyStatus.DESTROYED) {
            throw new CryptoException(CryptoErrorCode.KEY_DESTROYED,
                    "key version " + version + " has been destroyed");
        }
        return key;
    }

    public List<KeyInfo> listKeys() {
        return keys.values().stream()
                .map(k -> new KeyInfo(k.getVersion(), k.getStatus()))
                .sorted(Comparator.comparingInt(KeyInfo::version))
                .toList();
    }

    public int getActiveVersion() {
        return activeVersion;
    }

    private KeyVersion requireExisting(int version) {
        KeyVersion key = keys.get(version);
        if (key == null) {
            throw new CryptoException(CryptoErrorCode.UNKNOWN_KEY_VERSION,
                    "unknown key version " + version);
        }
        return key;
    }

    /** Installs a fresh ACTIVE key and makes it the active version. Caller must hold the monitor. */
    private int installNewVersion() {
        byte[] material = new byte[KEY_BYTES];
        random.nextBytes(material);
        int newVersion = keys.keySet().stream().mapToInt(Integer::intValue).max().orElse(0) + 1;
        keys.put(newVersion, new KeyVersion(newVersion, material));
        activeVersion = newVersion;
        return newVersion;
    }
}
