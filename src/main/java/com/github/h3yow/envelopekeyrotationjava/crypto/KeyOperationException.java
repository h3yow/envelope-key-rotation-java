package com.github.h3yow.envelopekeyrotationjava.crypto;

/**
 * 密钥相关操作的统一异常，携带可区分的 {@link FailureReason}。
 *
 * <p>注意：异常信息中不得包含密钥材料、明文或密文内容。</p>
 */
public class KeyOperationException extends RuntimeException {

    private final FailureReason reason;
    private final Integer keyVersion;

    public KeyOperationException(FailureReason reason, String message) {
        this(reason, null, message);
    }

    public KeyOperationException(FailureReason reason, Integer keyVersion, String message) {
        super(message);
        this.reason = reason;
        this.keyVersion = keyVersion;
    }

    public FailureReason getReason() {
        return reason;
    }

    /** 涉及的密钥版本号（可能为 null），仅用于诊断，不含密钥材料。 */
    public Integer getKeyVersion() {
        return keyVersion;
    }
}
