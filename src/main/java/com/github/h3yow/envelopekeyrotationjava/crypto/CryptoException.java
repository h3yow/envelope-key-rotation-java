package com.github.h3yow.envelopekeyrotationjava.crypto;

/**
 * Exception carrying a {@link CryptoErrorCode}. Messages must never include
 * key material, plaintext, or derived secrets.
 */
public class CryptoException extends RuntimeException {

    private final CryptoErrorCode code;

    public CryptoException(CryptoErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public CryptoErrorCode getCode() {
        return code;
    }
}
