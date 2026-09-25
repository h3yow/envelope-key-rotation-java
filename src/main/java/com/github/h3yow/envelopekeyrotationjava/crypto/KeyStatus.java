package com.github.h3yow.envelopekeyrotationjava.crypto;

/**
 * 密钥版本的生命周期状态。
 *
 * <p>状态机：ACTIVE -&gt; DECRYPT_ONLY -&gt; DISABLED -&gt; DESTROYED，
 * 其中 ACTIVE 也可直接停用；所有迁移不可逆。任意时刻至多一个 ACTIVE 版本。</p>
 */
public enum KeyStatus {
    /** 当前活跃版本：可用于加密与解密，全局唯一。 */
    ACTIVE,
    /** 已被轮换取代：仅可用于解密历史密文，不再用于加密。 */
    DECRYPT_ONLY,
    /** 已停用：不可用于加密或解密，但密钥材料仍保留，可进一步销毁。 */
    DISABLED,
    /** 已销毁：密钥材料已清零，不可恢复，任何加解密请求均被拒绝。 */
    DESTROYED
}
