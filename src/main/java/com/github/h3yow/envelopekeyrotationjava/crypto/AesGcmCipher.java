package com.github.h3yow.envelopekeyrotationjava.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * AES-GCM 原语封装：用于数据密钥（DEK）的包裹/解包以及业务数据加解密。
 *
 * <p>认证失败统一映射为 {@link FailureReason#CIPHERTEXT_TAMPERED}，不泄露内部细节。</p>
 */
final class AesGcmCipher {

    static final int KEY_BYTES = 32;   // AES-256
    static final int IV_BYTES = 12;    // GCM 标准 96 位 IV
    static final int TAG_BITS = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    private AesGcmCipher() {
    }

    static byte[] generateKey() {
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        return key;
    }

    static byte[] randomIv() {
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        return iv;
    }

    static byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encrypt failed", e);
        }
    }

    static byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            // 认证标签校验失败或密文损坏：统一判定为篡改，不区分细节以免成为解密预言机
            throw new KeyOperationException(FailureReason.CIPHERTEXT_TAMPERED,
                    "ciphertext integrity check failed");
        }
    }
}
