package com.github.h3yow.envelopekeyrotationjava.crypto;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Facade combining {@link KeyManager} and {@link EnvelopeCipher}.
 *
 * <p>Decryption always uses the key version embedded in the ciphertext; it
 * never falls back to another key. Failures surface as {@link CryptoException}
 * with a distinguishable {@link CryptoErrorCode}.</p>
 */
@Service
public class CryptoService {

    private final KeyManager keyManager;

    public CryptoService() {
        this.keyManager = new KeyManager();
    }

    /** Encrypts with the current ACTIVE key. Returns the versioned envelope. */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            throw new CryptoException(CryptoErrorCode.INVALID_ARGUMENT, "plaintext must not be null");
        }
        KeyVersion key = keyManager.requireActiveForEncrypt();
        return EnvelopeCipher.encrypt(key.getMaterial(), key.getVersion(),
                plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /** Decrypts using exactly the key version carried by the ciphertext. */
    public String decrypt(String ciphertext) {
        int version = EnvelopeCipher.extractVersion(ciphertext);
        KeyVersion key = keyManager.requireForDecrypt(version);
        byte[] plain = EnvelopeCipher.decrypt(key.getMaterial(), ciphertext);
        return new String(plain, StandardCharsets.UTF_8);
    }

    /** Unconditional rotation: always installs a fresh active version. */
    public KeyManager.RotationResult rotate() {
        return keyManager.rotate();
    }

    /**
     * Rotates the active key. If {@code expectedVersion} is non-null, the
     * rotation only happens when the current active version still matches it,
     * which makes concurrent rotation requests converge to a single result.
     */
    public KeyManager.RotationResult rotate(Integer expectedVersion) {
        return expectedVersion == null
                ? keyManager.rotate()
                : keyManager.rotate(expectedVersion);
    }

    /** Disables a key (decrypt-only). Irreversible. */
    public void disableKey(int version) {
        keyManager.disable(version);
    }

    /** Destroys a key (material erased, no decrypt). Irreversible. */
    public void destroyKey(int version) {
        keyManager.destroy(version);
    }

    public List<KeyManager.KeyInfo> listKeys() {
        return keyManager.listKeys();
    }

    public int getActiveVersion() {
        return keyManager.getActiveVersion();
    }
}
