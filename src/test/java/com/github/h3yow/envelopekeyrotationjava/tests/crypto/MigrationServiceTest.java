package com.github.h3yow.envelopekeyrotationjava.tests.crypto;

import com.github.h3yow.envelopekeyrotationjava.crypto.Ciphertext;
import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.InMemoryCiphertextStore;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.crypto.MigrationReport;
import com.github.h3yow.envelopekeyrotationjava.crypto.MigrationService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 批量迁移与版本边界测试：每个用例打印场景、判定依据与结果。
 */
class MigrationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(MigrationServiceTest.class);

    private record Fixture(KeyManager km, InMemoryCiphertextStore store, MigrationService service,
                           Map<String, byte[]> expectedPlaintexts) {}

    /** 构造：v1 下写入 n 条记录，随后轮换到 v2，返回夹具。 */
    private Fixture seededStore(int n) {
        KeyManager km = new KeyManager();
        InMemoryCiphertextStore store = new InMemoryCiphertextStore();
        km.setCiphertextStore(store);
        MigrationService service = new MigrationService(km, store);
        Map<String, byte[]> expected = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) {
            byte[] pt = ("record-" + i).getBytes(StandardCharsets.UTF_8);
            store.put("id-" + i, km.encrypt(pt));
            expected.put("id-" + i, pt);
        }
        int newActive = km.rotate();
        log.info("fixture seeded: records={}, migratedFrom=v1, activeVersion={}", n, newActive);
        return new Fixture(km, store, service, expected);
    }

    private static void assertAllReadableAndCorrect(Fixture f) {
        f.expectedPlaintexts().forEach((id, pt) -> {
            String ct = f.store().read(id).orElseThrow();
            assertArrayEquals(pt, f.km().decrypt(ct), "plaintext must be identical for " + id);
        });
    }

    private static void assertAllAtVersion(Fixture f, int version) {
        f.store().snapshot().forEach((id, ct) ->
                assertEquals(version, Ciphertext.parse(ct).keyVersion(),
                        "record " + id + " must be at version " + version));
    }

    @Test
    void batchMigrationReencryptsToLatestAndPlaintextIdentical() {
        Fixture f = seededStore(20);
        int target = f.km().activeVersion().orElseThrow();

        MigrationReport report = f.service().migrateAll();
        log.info("scenario=batch-migration: target={}, report={}", target, report);

        assertEquals(20, report.total());
        assertEquals(20, report.migrated());
        assertEquals(0, report.alreadyCurrent());
        assertTrue(report.isComplete());
        assertAllAtVersion(f, target);
        assertAllReadableAndCorrect(f);
        log.info("scenario=batch-migration: PASS, all 20 records at v{}, plaintexts identical", target);
    }

    @Test
    void migrationIsIdempotentAcrossRepeatedRuns() {
        Fixture f = seededStore(10);
        f.service().migrateAll();
        Map<String, String> afterFirst = f.store().snapshot();

        MigrationReport second = f.service().migrateAll();
        MigrationReport third = f.service().migrateAll();
        log.info("scenario=idempotent-rerun: second={} third={}", second, third);

        assertEquals(0, second.migrated(), "second run must not re-migrate");
        assertEquals(10, second.alreadyCurrent());
        assertEquals(0, third.migrated(), "third run must not re-migrate");
        assertEquals(afterFirst, f.store().snapshot(), "repeated runs must not change ciphertexts");
        assertAllReadableAndCorrect(f);
        log.info("scenario=idempotent-rerun: PASS, ciphertexts stable across 3 runs");
    }

    @Test
    void interruptedMigrationResumesWithoutReprocessing() {
        Fixture f = seededStore(10);
        List<String> allIds = List.copyOf(f.expectedPlaintexts().keySet());
        List<String> firstHalf = allIds.subList(0, 4);

        // 模拟中断：只处理完前 4 条
        MigrationReport partial = f.service().migrateBatch(firstHalf);
        Map<String, String> afterPartial = f.store().snapshot();
        log.info("scenario=resume-after-interrupt: partial={}", partial);
        assertEquals(4, partial.migrated());

        // 续跑：全量重跑，已处理的 4 条不得被重新处理
        MigrationReport resumed = f.service().migrateAll();
        log.info("scenario=resume-after-interrupt: resumed={}", resumed);
        assertEquals(6, resumed.migrated(), "only the unprocessed records may be migrated");
        assertEquals(4, resumed.alreadyCurrent(), "processed records must be skipped, not reprocessed");
        for (String id : firstHalf) {
            assertEquals(afterPartial.get(id), f.store().read(id).orElseThrow(),
                    "processed record must not be re-encrypted or rolled back: " + id);
        }
        assertAllAtVersion(f, f.km().activeVersion().orElseThrow());
        assertAllReadableAndCorrect(f);
        log.info("scenario=resume-after-interrupt: PASS, resumed from breakpoint, no reprocessing");
    }

    @Test
    void concurrentMigratorsConvergeToSameResult() throws Exception {
        Fixture f = seededStore(30);
        List<String> ids = List.copyOf(f.expectedPlaintexts().keySet());
        int target = f.km().activeVersion().orElseThrow();

        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch gate = new CountDownLatch(1);
        Future<MigrationReport> m1 = pool.submit(() -> { gate.await(); return f.service().migrateBatch(ids); });
        Future<MigrationReport> m2 = pool.submit(() -> { gate.await(); return f.service().migrateBatch(ids); });
        gate.countDown();
        MigrationReport r1 = m1.get(30, TimeUnit.SECONDS);
        MigrationReport r2 = m2.get(30, TimeUnit.SECONDS);
        pool.shutdown();
        log.info("scenario=concurrent-migrators: r1={} r2={}", r1, r2);

        assertTrue(r1.isComplete() && r2.isComplete(), "both migrators must complete without failures");
        assertEquals(30, r1.migrated() + r2.migrated(),
                "each record must be migrated exactly once across both migrators");
        assertEquals(30, r1.alreadyCurrent() + r2.alreadyCurrent(),
                "the losing migrator must observe records as already current");
        assertAllAtVersion(f, target);
        assertAllReadableAndCorrect(f);
        log.info("scenario=concurrent-migrators: PASS, converged, no duplicate migration");
    }

    @Test
    void migrationDuringConcurrentReadWriteIsConsistent() throws Exception {
        Fixture f = seededStore(20);
        List<String> ids = List.copyOf(f.expectedPlaintexts().keySet());

        ExecutorService pool = Executors.newFixedThreadPool(4);
        CountDownLatch gate = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        // 两个读者：迁移期间反复读老记录，明文必须始终正确
        for (int r = 0; r < 2; r++) {
            futures.add(pool.submit(() -> {
                gate.await();
                for (int round = 0; round < 100; round++) {
                    for (String id : ids) {
                        byte[] pt = f.km().decrypt(f.store().read(id).orElseThrow());
                        assertArrayEquals(f.expectedPlaintexts().get(id), pt,
                                "read during migration must return correct plaintext for " + id);
                    }
                }
                return null;
            }));
        }
        // 一个写者：迁移期间持续写入新记录（当前版本）
        futures.add(pool.submit(() -> {
            gate.await();
            for (int i = 0; i < 20; i++) {
                byte[] pt = ("live-write-" + i).getBytes(StandardCharsets.UTF_8);
                f.store().put("live-" + i, f.km().encrypt(pt));
                assertArrayEquals(pt, f.km().decrypt(f.store().read("live-" + i).orElseThrow()));
            }
            return null;
        }));
        // 一个迁移者
        Future<MigrationReport> migrator = pool.submit(() -> { gate.await(); return f.service().migrateBatch(ids); });
        gate.countDown();
        MigrationReport report = migrator.get(60, TimeUnit.SECONDS);
        for (Future<?> x : futures) {
            x.get(60, TimeUnit.SECONDS);
        }
        pool.shutdown();
        log.info("scenario=migration-with-live-traffic: report={}", report);

        assertTrue(report.isComplete());
        assertEquals(20, report.migrated());
        assertAllReadableAndCorrect(f);
        log.info("scenario=migration-with-live-traffic: PASS, reads consistent during migration");
    }

    @Test
    void destroyRejectedWhileVersionStillReferenced() {
        Fixture f = seededStore(5);
        int v1 = 1; // 轮换后 v1 处于 DECRYPT_ONLY，仍被 5 条密文引用

        // 仍有密文引用：拒绝销毁，原因可区分（引用检查优先于状态迁移检查）
        KeyOperationException ex = assertThrows(KeyOperationException.class, () -> f.km().destroy(v1));
        log.info("scenario=destroy-boundary: rejected reason={}, keyVersion={}", ex.getReason(), ex.getKeyVersion());
        assertEquals(FailureReason.KEY_IN_USE, ex.getReason());
        assertFalse(f.km().listVersions().get(0).isMaterialDestroyed(), "rejected destroy must not clear material");

        // 迁移完成后不再有任何引用：停用并销毁成功
        MigrationReport report = f.service().migrateAll();
        assertTrue(report.isComplete());
        f.km().deactivate(v1);
        f.km().destroy(v1);
        assertTrue(f.km().listVersions().get(0).isMaterialDestroyed());
        log.info("scenario=destroy-boundary: PASS, destroy allowed only after references migrated away");
    }

    @Test
    void versionLimitRejectsRotationAndMigration() {
        KeyManager km = new KeyManager(2); // 上限 2 个版本
        InMemoryCiphertextStore store = new InMemoryCiphertextStore();
        km.setCiphertextStore(store);
        MigrationService service = new MigrationService(km, store);
        store.put("id-0", km.encrypt("x".getBytes(StandardCharsets.UTF_8)));

        int v2 = km.rotate(); // 达到上限
        log.info("scenario=version-limit: rotated to v{}, versionCount={}/{}", v2, km.versionCount(), km.maxVersions());

        KeyOperationException rotEx = assertThrows(KeyOperationException.class, km::rotate);
        log.info("scenario=version-limit: rotate rejected reason={}", rotEx.getReason());
        assertEquals(FailureReason.VERSION_LIMIT_EXCEEDED, rotEx.getReason());

        KeyOperationException migEx = assertThrows(KeyOperationException.class, service::migrateAll);
        log.info("scenario=version-limit: migration rejected reason={}", migEx.getReason());
        assertEquals(FailureReason.VERSION_LIMIT_EXCEEDED, migEx.getReason());

        // 上限拒绝不等于数据损坏：老密文仍可解密，版本未被悄悄淘汰
        assertEquals(2, km.versionCount(), "no version may be silently evicted");
        assertArrayEquals("x".getBytes(StandardCharsets.UTF_8), km.decrypt(store.read("id-0").orElseThrow()));
        log.info("scenario=version-limit: PASS, both rotation and migration clearly rejected at capacity");
    }

    @Test
    void reencryptOnCurrentVersionCiphertextIsPassThrough() {
        KeyManager km = new KeyManager();
        String ct = km.encrypt("already-current".getBytes(StandardCharsets.UTF_8));
        String again = km.reencrypt(ct);
        log.info("scenario=reencrypt-idempotent: input==output? {}", ct.equals(again));
        assertEquals(ct, again, "re-encrypting a current-version ciphertext must be a no-op");
    }
}
