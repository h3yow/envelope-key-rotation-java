package com.github.h3yow.envelopekeyrotationjava.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Versioned AEAD envelope format. Binary layout before Base64url encoding:
 * <pre>
 *   magic(2 bytes, 0xEK) | version(4 bytes, big-endian) | iv(12 bytes) | ciphertext || GCM tag(16 bytes)
 * </pre>
 * The version header is bound into the GCM AAD so it cannot be swapped without
 * detection. Parsing and cryptographic failures are mapped to distinct
 * {@link CryptoErrorCode}s; no partial plaintext is ever returned.
 */
final class EnvelopeCipher {

    private static final byte[] MAGIC = {'E', 'K'};
    private static final int HEADER_LEN = MAGIC.length + Integer.BYTES;
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private EnvelopeCipher() {
    }

    static String encrypt(byte[] keyMaterial, int version, byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_LEN];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyMaterial, "AES"),
                    new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad(version));
            byte[] sealed = cipher.doFinal(plaintext);
            ByteBuffer buf = ByteBuffer.allocate(HEADER_LEN + IV_LEN + sealed.length);
            buf.put(MAGIC).putInt(version).put(iv).put(sealed);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(buf.array());
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.INVALID_ARGUMENT,
                    "encryption failed for key version " + version);
        }
    }

    /** Decodes the envelope and returns the embedded key version. */
    static int extractVersion(String encoded) {
        return parse(encoded).version();
    }

    static byte[] decrypt(byte[] keyMaterial, String encoded) {
        Envelope env = parse(encoded);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyMaterial, "AES"),
                    new GCMParameterSpec(TAG_BITS, env.iv()));
            cipher.updateAAD(aad(env.version()));
            return cipher.doFinal(env.sealed());
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.INTEGRITY_CHECK_FAILED,
                    "integrity check failed for key version " + env.version());
        }
    }

    private record Envelope(int version, byte[] iv, byte[] sealed) {
    }

    private static Envelope parse(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new CryptoException(CryptoErrorCode.MALFORMED_CIPHERTEXT, "ciphertext is empty");
        }
        final byte[] raw;
        try {
            raw = Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoErrorCode.MALFORMED_CIPHERTEXT, "ciphertext is not valid Base64url");
        }
        if (raw.length < MAGIC.length) {
            throw new CryptoException(CryptoErrorCode.MALFORMED_CIPHERTEXT, "ciphertext too short for header");
        }
        if (raw[0] != MAGIC[0] || raw[1] != MAGIC[1]) {
            throw new CryptoException(CryptoErrorCode.MALFORMED_CIPHERTEXT, "unrecognized envelope format");
        }
        if (raw.length < HEADER_LEN) {
            throw new CryptoException(CryptoErrorCode.VERSION_MISSING, "ciphertext carries no key-version header");
        }
        ByteBuffer buf = ByteBuffer.wrap(raw);
        buf.position(MAGIC.length);
        int version = buf.getInt();
        if (version <= 0) {
            throw new CryptoException(CryptoErrorCode.VERSION_MISSING, "invalid key-version header: " + version);
        }
        if (raw.length < HEADER_LEN + IV_LEN + (TAG_BITS / 8) + 1) {
            throw new CryptoException(CryptoErrorCode.MALFORMED_CIPHERTEXT, "ciphertext truncated");
        }
        byte[] iv = new byte[IV_LEN];
        buf.get(iv);
        byte[] sealed = new byte[buf.remaining()];
        buf.get(sealed);
        return new Envelope(version, iv, sealed);
    }

    private static byte[] aad(int version) {
        return ByteBuffer.allocate(MAGIC.length + Integer.BYTES).put(MAGIC).putInt(version).array();
    }
}
