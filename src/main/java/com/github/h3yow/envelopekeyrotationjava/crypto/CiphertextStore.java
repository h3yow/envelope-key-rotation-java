package com.github.h3yow.envelopekeyrotationjava.crypto;

import java.util.Map;
import java.util.Optional;

/**
 * 密文存储抽象：迁移过程中读写的最小契约。
 *
 * <p>迁移的并发收敛依赖 {@link #compareAndSet}：只有当前值仍等于迁移前读到的值时才写回，
 * 否则视为被并发修改，调用方重新读取并评估，保证多个迁移者最终收敛到同一结果。</p>
 */
public interface CiphertextStore {

    /** 读取记录当前密文；不存在返回空。 */
    Optional<String> read(String id);

    /**
     * 仅当 id 当前值等于 expected 时替换为 newValue。
     *
     * @return 是否替换成功
     */
    boolean compareAndSet(String id, String expected, String newValue);

    /** 写入或覆盖记录（业务正常读写路径使用）。 */
    void put(String id, String ciphertext);

    /** 全部记录的瞬时快照（id -> ciphertext），用于扫描与引用计数。 */
    Map<String, String> snapshot();
}
