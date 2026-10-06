package com.github.h3yow.envelopekeyrotationjava.storage;

/**
 * 存储中的一条密文记录（不可变）。
 *
 * @param id         记录标识
 * @param ciphertext 自描述密文（EK1.&lt;version&gt;.&lt;payload&gt;）
 * @param keyVersion 密文当前引用的密钥版本
 */
public record StoredRecord(String id, String ciphertext, int keyVersion) {
}
