package com.github.h3yow.envelopekeyrotationjava.tests.crypto;

import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyStatus;
import com.github.h3yow.envelopekeyrotationjava.storage.CiphertextStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 版本治理边界测试：
 * <ol>
 *   <li>仍被密文引用的版本拒绝销毁，原因为 KEY_STILL_REFERENCED，且与停用/非法迁移等原因可区分；</li>
 *   <li>保留版本数达到上限时，轮换以 VERSION_LIMIT_EXCEEDED 被明确拒绝，不会悄悄丢版本；</li>
 *   <li>迁移把引用搬空、旧版本停用+销毁后，容量释放，轮换恢复；</li>
 *   <li>销毁版本不计入保留数，引用检查器可替换（模拟存储重建等场景）。</li>
 * </ol>
 */
class KeyGovernanceTest {

    private static final Logger log = LoggerFactory.getLogger(KeyGovernanceTest.class);

    private static KeyOperationException expect(FailureReason expected, Runnable action) {
        KeyOperationException ex = assertThrows(KeyOperationException.class, action::run);
        log.info("assertion basis: expectedReason={}, actualReason={}, keyVersion={}",
                expected, ex.getReason(), ex.getKeyVersion());
        assertEquals(expected, ex.getReason());
        return ex;
    }

    private CiphertextStore attachStore(KeyManager km) {
        CiphertextStore store = new CiphertextStore();
        km.setReferenceChecker(store::isReferenced);
        return store;
    }

    @Test
    void destroyRejectedWhileVersionReferencedAndReasonIsDistinct() {
        KeyManager km = new KeyManager(32);
        CiphertextStore store = attachStore(km);
        int v1 = km.activeVersion().orElseThrow();
        store.save("rec-1", km.encrypt("a".getBytes(StandardCharsets.UTF_8)));
        store.save("rec-2", km.encrypt("b".getBytes(StandardCharsets.UTF_8)));

        // v1 是 ACTIVE：直接销毁本应是 ILLEGAL_STATE_TRANSITION；引用检查先于状态迁移，
        // 只要还被引用，结论必须统一为 KEY_STILL_REFERENCED
        expect(FailureReason.KEY_STILL_REFERENCED, () -> km.destroy(v1));
        log.info("场景: ACTIVE 版本仍被 2 条密文引用 -> 销毁以 KEY_STILL_REFERENCED 拒绝（优先于状态非法）");

        // 轮换后 v1 为 DECRYPT_ONLY，仍被引用，同样拒绝
        int v2 = km.rotate();
        expect(FailureReason.KEY_STILL_REFERENCED, () -> km.destroy(v1));
        // 即使先停用，引用还在，销毁依旧拒绝——拒绝原因必须能与"已停用/已销毁"区分开
        km.deactivate(v1);
        expect(FailureReason.KEY_STILL_REFERENCED, () -> km.destroy(v1));
        expect(FailureReason.KEY_DISABLED, () -> km.decrypt(store.get("rec-1").orElseThrow().ciphertext()));
        log.info("场景: DECRYPT_ONLY/DISABLED 版本仍被引用 -> 销毁仍以 KEY_STILL_REFERENCED 拒绝，"
                + "且与 KEY_DISABLED 可区分");

        // 引用未清零前，材料与状态保持原样（无半销毁）
        assertEquals(KeyStatus.DISABLED, km.listVersions().get(0).getStatus());
        assertFalse(km.listVersions().get(0).isMaterialDestroyed());
    }

    @Test
    void destroyAllowedAfterReferencesMigratedAway() {
        KeyManager km = new KeyManager(32);
        CiphertextStore store = attachStore(km);
        int v1 = km.activeVersion().orElseThrow();
        store.save("rec-1", km.encrypt("a".getBytes(StandardCharsets.UTF_8)));
        int v2 = km.rotate();

        // 把唯一一条记录搬到新版本（此处直接用 store 原子替换模拟迁移结果）
        String reencrypted = km.encrypt("a".getBytes(StandardCharsets.UTF_8));
        String oldCt = store.get("rec-1").orElseThrow().ciphertext();
        assertTrue(store.replaceIfUnchanged("rec-1", oldCt, reencrypted, v2));
        assertEquals(0, store.referenceCount(v1));
        assertFalse(store.isReferenced(v1));
        log.info("场景: 引用迁移清零 -> v1 引用数=0, v2 引用数={}", store.referenceCount(v2));

        // 无引用：停用后销毁成功
        km.deactivate(v1);
        km.destroy(v1);
        assertEquals(KeyStatus.DESTROYED, km.listVersions().get(0).getStatus());
        assertTrue(km.listVersions().get(0).isMaterialDestroyed());
        log.info("场景: 引用清零后停用+销毁 -> v1 DESTROYED，边界清晰");
    }

    @Test
    void rotationRejectedWhenVersionLimitReached() {
        KeyManager km = new KeyManager(3); // 最多保留 3 个版本
        int v1 = km.activeVersion().orElseThrow();
        assertEquals(3, km.maxVersions());
        assertEquals(1, km.retainedVersionCount());

        int v2 = km.rotate();
        int v3 = km.rotate();
        log.info("场景: 保留上限=3，已轮换至 v{}（retained={}）", v3, km.retainedVersionCount());
        assertEquals(3, km.retainedVersionCount());

        // 第四次轮换必须被明确拒绝，而不是悄悄淘汰 v1
        KeyOperationException ex = expect(FailureReason.VERSION_LIMIT_EXCEEDED, km::rotate);
        assertEquals(v3, km.activeVersion().orElseThrow(), "拒绝轮换后活跃版本不得变化");
        assertEquals(3, km.listVersions().size(), "最老版本绝不能被悄悄丢弃");
        Set<Integer> versions = new HashSet<>(km.listVersions().stream().map(k -> k.getVersion()).toList());
        assertEquals(Set.of(v1, v2, v3), versions, "三个版本必须都还在");
        log.info("场景: 达到上限后轮换拒绝 -> message=\"{}\"", ex.getMessage().split(";")[0]);

        // 被拒绝之后服务仍正常：用当前版本加解密可用
        byte[] msg = "still-serving".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(msg, km.decrypt(km.encrypt(msg)));
    }

    @Test
    void destroyingOldVersionReleasesCapacityForRotation() {
        KeyManager km = new KeyManager(2);
        CiphertextStore store = attachStore(km);
        int v1 = km.activeVersion().orElseThrow();
        store.save("rec-1", km.encrypt("x".getBytes(StandardCharsets.UTF_8)));
        int v2 = km.rotate();

        // 已到上限
        expect(FailureReason.VERSION_LIMIT_EXCEEDED, km::rotate);
        log.info("场景: 上限=2 且满员 -> 轮换被拒，等待旧版本下线释放容量");

        // 把数据搬到 v2、停用并销毁 v1
        String oldCt = store.get("rec-1").orElseThrow().ciphertext();
        assertTrue(store.replaceIfUnchanged("rec-1", oldCt,
                km.encrypt("x".getBytes(StandardCharsets.UTF_8)), v2));
        km.deactivate(v1);
        km.destroy(v1);
        assertEquals(1, km.retainedVersionCount(), "销毁后的版本不再占用保留名额");

        int v3 = km.rotate();
        assertEquals(v2 + 1, v3);
        assertEquals(2, km.retainedVersionCount());
        log.info("场景: 旧版本销毁释放容量 -> 轮换恢复, newActiveVersion={}", v3);
        // 数据依旧可读（现在挂在 v2 上）
        assertArrayEquals("x".getBytes(StandardCharsets.UTF_8),
                km.decrypt(store.get("rec-1").orElseThrow().ciphertext()));
    }

    @Test
    void referencedVersionWithoutDestroyStillBlocksRepeatedly() {
        // 边界稳定性：只要引用还在，反复销毁尝试得到同一个可区分结论，状态不被推进
        KeyManager km = new KeyManager(32);
        CiphertextStore store = attachStore(km);
        int v1 = km.activeVersion().orElseThrow();
        store.save("only", km.encrypt("y".getBytes(StandardCharsets.UTF_8)));
        km.rotate(); // v1 -> DECRYPT_ONLY
        for (int i = 0; i < 3; i++) {
            expect(FailureReason.KEY_STILL_REFERENCED, () -> km.destroy(v1));
        }
        assertEquals(KeyStatus.DECRYPT_ONLY, km.listVersions().get(0).getStatus(),
                "被引用拒绝不得改变密钥状态");
        log.info("场景: 连续 3 次销毁被引用版本 -> 结论一致 KEY_STILL_REFERENCED，状态停留在 DECRYPT_ONLY");
    }
}
