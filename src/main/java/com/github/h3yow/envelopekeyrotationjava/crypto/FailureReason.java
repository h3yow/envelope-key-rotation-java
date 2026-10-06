package com.github.h3yow.envelopekeyrotationjava.crypto;

/**
 * 加解密与密钥生命周期操作失败的可区分原因。
 */
public enum FailureReason {
    /** 密文中未携带密钥版本信息。 */
    VERSION_MISSING,
    /** 密文结构无法解析（长度、编码、分段错误等）。 */
    CIPHERTEXT_MALFORMED,
    /** 密文完整性校验失败（被篡改或密钥不匹配）。 */
    CIPHERTEXT_TAMPERED,
    /** 密文引用的密钥版本不存在。 */
    KEY_NOT_FOUND,
    /** 密钥已停用，拒绝加解密。 */
    KEY_DISABLED,
    /** 密钥已销毁，拒绝加解密。 */
    KEY_DESTROYED,
    /** 当前没有可用于加密的活跃密钥版本。 */
    NO_ACTIVE_KEY,
    /** 生命周期状态迁移非法或操作不被允许。 */
    ILLEGAL_STATE_TRANSITION,
    /** 密钥版本仍被密文引用，拒绝销毁。 */
    KEY_IN_USE,
    /** 保留版本数已达上限，拒绝新的轮换或迁移请求。 */
    VERSION_LIMIT_EXCEEDED
}
