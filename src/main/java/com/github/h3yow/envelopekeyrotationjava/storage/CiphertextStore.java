package com.github.h3yow.envelopekeyrotationjava.storage;

import com.github.h3yow.envelopekeyrotationjava.crypto.Ciphertext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 进程内密文存储：模拟"老数据"所在的数据库表。
 *
 * <p>每条记录以自描述密文保存，并维护各密钥版本的引用计数。
 * 密文替换与引用计数调整在同一把锁内原子完成，保证迁移期间读到的
 * 永远是一份完整的旧密文或新密文，不会读到半成品；
 * "某版本是否仍被引用"的结论也与记录内容严格一致。</p>
 */
@Component
public class CiphertextStore {

    private static final Logger log = LoggerFactory.getLogger(CiphertextStore.class);

    private final ConcurrentHashMap<String, StoredRecord> records = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, AtomicInteger> refCounts = new ConcurrentHashMap<>();
    private final Object storeLock = new Object();

    public CiphertextStore() {
    }

    /**
     * 保存（或覆盖）一条已加密记录，并计入其版本引用。
     * 版本号以密文自描述字段为准，避免调用方传错导致引用计数失真。
     */
    public StoredRecord save(String id, String ciphertext) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("record id must not be blank");
        }
        int version = Ciphertext.parse(ciphertext).keyVersion();
        synchronized (storeLock) {
            StoredRecord existing = records.get(id);
            StoredRecord record = new StoredRecord(id, ciphertext, version);
            records.put(id, record);
            if (existing == null) {
                refCounts.computeIfAbsent(version, k -> new AtomicInteger()).incrementAndGet();
            } else if (existing.keyVersion() != version) {
                decrementRef(existing.keyVersion());
                refCounts.computeIfAbsent(version, k -> new AtomicInteger()).incrementAndGet();
            }
            log.info("store save ok: id={}, keyVersion={}, overwrite={}",
                    id, version, existing != null);
            return record;
        }
    }

    /** 读取一条记录；不存在返回空。读取到的永远是某次替换前或替换后的完整密文。 */
    public Optional<StoredRecord> get(String id) {
        return Optional.ofNullable(records.get(id));
    }

    /** 全部记录快照，按 id 升序，用于遍历与诊断。 */
    public List<StoredRecord> all() {
        List<StoredRecord> snapshot = new ArrayList<>(records.values());
        snapshot.sort(Comparator.comparing(StoredRecord::id));
        return snapshot;
    }

    /** 全部记录 id，按升序，用于批量迁移选择。 */
    public List<String> ids() {
        List<String> snapshot = new ArrayList<>(records.keySet());
        snapshot.sort(Comparator.naturalOrder());
        return snapshot;
    }

    /**
     * 仅当记录当前密文与 expectedCiphertext 一致时，原子替换为新密文，
     * 同时把引用计数从 oldVersion 调整到 newVersion。
     *
     * <p>这是迁移幂等与并发收敛的关键：CAS 失败说明记录已被其他迁移者处理过
     * （或已被新写入覆盖），本次跳过，绝不重复处理、绝不回退。</p>
     *
     * @return 替换成功返回 true；记录不存在或当前密文已不是预期值返回 false
     */
    public boolean replaceIfUnchanged(String id, String expectedCiphertext,
                                      String newCiphertext, int newVersion) {
        int parsedNewVersion = Ciphertext.parse(newCiphertext).keyVersion();
        if (parsedNewVersion != newVersion) {
            throw new IllegalArgumentException("declared newVersion does not match ciphertext");
        }
        synchronized (storeLock) {
            StoredRecord existing = records.get(id);
            if (existing == null || !existing.ciphertext().equals(expectedCiphertext)) {
                return false;
            }
            if (existing.keyVersion() == newVersion) {
                // 已经是目标版本：无需任何改动
                return false;
            }
            records.put(id, new StoredRecord(id, newCiphertext, newVersion));
            decrementRef(existing.keyVersion());
            refCounts.computeIfAbsent(newVersion, k -> new AtomicInteger()).incrementAndGet();
            log.info("store replace ok: id={}, keyVersion {} -> {}",
                    id, existing.keyVersion(), newVersion);
            return true;
        }
    }

    /** 当前仍引用指定版本的记录数量。 */
    public int referenceCount(int keyVersion) {
        synchronized (storeLock) {
            AtomicInteger counter = refCounts.get(keyVersion);
            return counter == null ? 0 : counter.get();
        }
    }

    /** 该版本是否仍被至少一条记录引用。 */
    public boolean isReferenced(int keyVersion) {
        return referenceCount(keyVersion) > 0;
    }

    private void decrementRef(int version) {
        AtomicInteger counter = refCounts.get(version);
        if (counter == null) {
            // 引用计数内部一致性不应被破坏；出现即缺陷，直接暴露
            throw new IllegalStateException("missing reference counter for version " + version);
        }
        int remaining = counter.decrementAndGet();
        if (remaining < 0) {
            throw new IllegalStateException("negative reference count for version " + version);
        }
    }

    /** 仅供诊断：当前各版本引用计数快照。 */
    public Map<Integer, Integer> referenceCountSnapshot() {
        synchronized (storeLock) {
            Map<Integer, Integer> snapshot = new java.util.TreeMap<>();
            refCounts.forEach((v, c) -> {
                if (c.get() > 0) {
                    snapshot.put(v, c.get());
                }
            });
            return snapshot;
        }
    }
}
