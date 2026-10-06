package com.github.h3yow.envelopekeyrotationjava.tests.storage;

import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.storage.CiphertextStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CiphertextStore 行为测试：记录存取、版本引用计数与 CAS 替换。
 */
class CiphertextStoreTest {

    private static final Logger log = LoggerFactory.getLogger(CiphertextStoreTest.class);

    private String encryptAt(KeyManager km, String plaintext) {
        return km.encrypt(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test
    void saveTracksReferenceCountsByCiphertextVersion() {
        KeyManager km = new KeyManager(32);
        CiphertextStore store = new CiphertextStore();
        int v1 = km.activeVersion().orElseThrow();

        store.save("a", encryptAt(km, "a"));
        store.save("b", encryptAt(km, "b"));
        assertEquals(2, store.referenceCount(v1));
        log.info("场景: 引用计数随写入增长 -> versions={}", store.referenceCountSnapshot());

        int v2 = km.rotate();
        // 覆盖保存 a：引用从 v1 搬到 v2
        store.save("a", encryptAt(km, "a2"));
        assertEquals(1, store.referenceCount(v1));
        assertEquals(1, store.referenceCount(v2));
        log.info("场景: 覆盖写入把引用搬到新版本 -> versions={}", store.referenceCountSnapshot());

        assertEquals(List.of("a", "b"), store.ids());
    }

    @Test
    void replaceIfUnchangedIsAtomicAndIdempotent() {
        KeyManager km = new KeyManager(32);
        CiphertextStore store = new CiphertextStore();
        int v1 = km.activeVersion().orElseThrow();
        String oldCt = encryptAt(km, "secret");
        store.save("r1", oldCt);

        int v2 = km.rotate();
        String newCt = encryptAt(km, "secret");

        // 第一次 CAS 成功，引用计数同步迁移
        assertTrue(store.replaceIfUnchanged("r1", oldCt, newCt, v2));
        assertEquals(0, store.referenceCount(v1), "旧版本引用必须清零");
        assertEquals(1, store.referenceCount(v2));
        log.info("场景: CAS 替换成功并迁移引用 -> versions={}", store.referenceCountSnapshot());

        // 第二次以旧密文为期望值：失败，不重复处理、不回退
        assertFalse(store.replaceIfUnchanged("r1", oldCt, newCt, v2));
        assertEquals(0, store.referenceCount(v1));
        assertEquals(1, store.referenceCount(v2), "重复 CAS 不得改变引用计数");
        assertEquals(newCt, store.get("r1").orElseThrow().ciphertext(), "记录不得被回退或重复改写");
        log.info("场景: 重复 CAS 不产生重复结果、不回退 -> r1.keyVersion={}",
                store.get("r1").orElseThrow().keyVersion());

        // 不存在的记录无法替换
        assertFalse(store.replaceIfUnchanged("missing", oldCt, newCt, v2));
    }

    @Test
    void recordsAreStoredAndReadBackInOrder() {
        KeyManager km = new KeyManager(32);
        CiphertextStore store = new CiphertextStore();
        store.save("z", encryptAt(km, "z"));
        store.save("a", encryptAt(km, "a"));
        store.save("m", encryptAt(km, "m"));
        assertEquals(List.of("a", "m", "z"), store.ids());
        assertEquals(3, store.all().size());
        assertTrue(store.get("a").isPresent());
        assertTrue(store.get("nope").isEmpty());
        log.info("场景: 记录按 id 有序枚举 -> ids={}", store.ids());
    }
}
