package com.github.h3yow.envelopekeyrotationjava.tests.migration;

import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.migration.BatchMigrationService;
import com.github.h3yow.envelopekeyrotationjava.migration.MigrationResult;
import com.github.h3yow.envelopekeyrotationjava.storage.CiphertextStore;
import com.github.h3yow.envelopekeyrotationjava.storage.StoredRecord;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 批量迁移测试：正确性、幂等重跑、中断续跑。
 *
 * <p>每个用例以 "场景:" 开头打印覆盖点与判定依据，便于从日志观察覆盖面。</p>
 */
class BatchMigrationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(BatchMigrationServiceTest.class);

    /** 测试夹具：密钥管理器 + 存储 + 迁移服务，并预置指定数量的旧版本密文。 */
    private record Fixture(KeyManager km, CiphertextStore store, BatchMigrationService migration,
                           int sourceVersion, int targetVersion, Map<String, String> plaintexts) {

        static Fixture setup(int recordCount) {
            KeyManager km = new KeyManager(32);
            CiphertextStore store = new CiphertextStore();
            BatchMigrationService migration = new BatchMigrationService(km, store);
            // 非 Spring 环境手动完成 @PostConstruct 的等价装配
            km.setReferenceChecker(store::isReferenced);

            int sourceVersion = km.activeVersion().orElseThrow();
            Map<String, String> plaintexts = new HashMap<>();
            for (int i = 0; i < recordCount; i++) {
                String id = "rec-" + String.format("%03d", i);
                String plaintext = "plaintext-" + i;
                plaintexts.put(id, plaintext);
                store.save(id, km.encrypt(plaintext.getBytes(StandardCharsets.UTF_8)));
            }
            int targetVersion = km.rotate();
            return new Fixture(km, store, migration, sourceVersion, targetVersion, plaintexts);
        }

        /** 断言全部记录的明文仍与迁移前一致。 */
        void assertPlaintextUnchanged() {
            for (StoredRecord r : store.all()) {
                byte[] got = km.decrypt(r.ciphertext());
                String expected = plaintexts.get(r.id());
                assertNotNull(expected, "unexpected record " + r.id());
                assertEquals(expected, new String(got, StandardCharsets.UTF_8),
                        "迁移前后明文必须逐字节一致: " + r.id());
            }
        }
    }

    @Test
    void migrateAllRewritesToTargetVersionAndPreservesPlaintext() {
        Fixture f = Fixture.setup(50);
        // 前提：全部记录都在旧版本
        assertEquals(50, f.store().referenceCount(f.sourceVersion()));
        assertEquals(0, f.store().referenceCount(f.targetVersion()));

        MigrationResult result = f.migration().migrateAll(null);

        log.info("场景: 全量迁移到最新版本 -> targetVersion={}, processed={}, skipped={}, failed={}, hasMore={}",
                result.targetVersion(), result.processed(), result.skipped(), result.failed(), result.hasMore());
        assertEquals(f.targetVersion(), result.targetVersion());
        assertEquals(50, result.processed());
        assertEquals(0, result.skipped());
        assertEquals(0, result.failed());
        assertFalse(result.hasMore());
        assertNull(result.nextCursor());
        assertEquals(0, f.store().referenceCount(f.sourceVersion()), "旧版本不应再有引用");
        assertEquals(50, f.store().referenceCount(f.targetVersion()));
        f.assertPlaintextUnchanged();
    }

    @Test
    void repeatedMigrationIsIdempotent() {
        Fixture f = Fixture.setup(30);

        MigrationResult first = f.migration().migrateAll(null);
        MigrationResult second = f.migration().migrateAll(null);
        MigrationResult third = f.migration().migrateAll(null);

        log.info("场景: 同一批数据重复迁移 -> 第一次 processed={}, 第二次 processed={}/skipped={}, "
                        + "第三次 processed={}/skipped={}",
                first.processed(), second.processed(), second.skipped(),
                third.processed(), third.skipped());
        assertEquals(30, first.processed());
        assertEquals(0, second.processed(), "第二遍不得重复处理");
        assertEquals(30, second.skipped());
        assertEquals(0, third.processed(), "第三遍不得重复处理");
        assertEquals(30, third.skipped());

        // 记录内容稳定：第三遍之后再读，明文与版本结论一致
        Map<String, StoredRecord> afterSecond = new HashMap<>();
        f.store().all().forEach(r -> afterSecond.put(r.id(), r));
        f.migration().migrateAll(null);
        for (StoredRecord r : f.store().all()) {
            assertEquals(afterSecond.get(r.id()).ciphertext(), r.ciphertext(),
                    "幂等重跑不得改写已迁好的密文: " + r.id());
        }
        assertEquals(30, f.store().referenceCount(f.targetVersion()));
        f.assertPlaintextUnchanged();
    }

    @Test
    void interruptedMigrationResumesFromCursorWithoutReprocessing() {
        // 25 条数据，每片 10 条：10 + 10 + 5，模拟两次中断后续跑
        Fixture f = Fixture.setup(25);

        MigrationResult r1 = f.migration().migrateBatch(null, 10, null);
        log.info("场景: 分片 1 -> processed={}, candidates={}, hasMore={}, nextCursor 已生成={}",
                r1.processed(), r1.totalCandidates(), r1.hasMore(), r1.nextCursor() != null);
        assertEquals(10, r1.processed());
        assertTrue(r1.hasMore());
        assertNotNull(r1.nextCursor());
        // 中断点：10 条在新版本，15 条仍在旧版本
        assertEquals(10, f.store().referenceCount(f.targetVersion()));
        assertEquals(15, f.store().referenceCount(f.sourceVersion()));

        MigrationResult r2 = f.migration().migrateBatch(null, 10, r1.nextCursor());
        log.info("场景: 中断后凭游标续跑分片 2 -> processed={}, skipped={}, hasMore={}",
                r2.processed(), r2.skipped(), r2.hasMore());
        assertEquals(10, r2.processed());
        assertEquals(0, r2.skipped(), "续跑不得重做已处理部分");
        assertTrue(r2.hasMore());

        MigrationResult r3 = f.migration().migrateBatch(null, 10, r2.nextCursor());
        log.info("场景: 续跑分片 3 收尾 -> processed={}, skipped={}, hasMore={}",
                r3.processed(), r3.skipped(), r3.hasMore());
        assertEquals(5, r3.processed());
        assertFalse(r3.hasMore());
        assertNull(r3.nextCursor());

        assertEquals(0, f.store().referenceCount(f.sourceVersion()));
        assertEquals(25, f.store().referenceCount(f.targetVersion()));
        f.assertPlaintextUnchanged();

        // 续跑完成后再全量跑一遍：全部跳过
        MigrationResult rerun = f.migration().migrateAll(null);
        assertEquals(0, rerun.processed());
        assertEquals(25, rerun.skipped());
        log.info("场景: 续跑完成后重跑 -> processed=0, skipped=25，已处理部分不重做、不回退");
    }

    @Test
    void resumingWithoutCursorAfterPartialProgressSkipsMigratedRecords() {
        // 部分迁移后丢失游标：从头重跑也必须安全——已迁的跳过、未迁的补齐
        Fixture f = Fixture.setup(12);
        f.migration().migrateBatch(null, 4, null); // 前 4 条已迁
        MigrationResult recovery = f.migration().migrateAll(null);
        log.info("场景: 无游标全量重跑做恢复 -> processed={}, skipped={}",
                recovery.processed(), recovery.skipped());
        assertEquals(8, recovery.processed());
        assertEquals(4, recovery.skipped());
        assertEquals(12, f.store().referenceCount(f.targetVersion()));
        f.assertPlaintextUnchanged();
    }

    @Test
    void explicitIdSubsetIsMigratedIndependently() {
        Fixture f = Fixture.setup(10);
        List<String> subset = List.of("rec-001", "rec-002", "rec-009");
        MigrationResult result = f.migration().migrateAll(subset);
        log.info("场景: 只迁指定 id 子集 -> processed={}, candidates={}", result.processed(),
                result.totalCandidates());
        assertEquals(3, result.processed());
        assertEquals(3, f.store().referenceCount(f.targetVersion()));
        assertEquals(7, f.store().referenceCount(f.sourceVersion()));
        // 未选中的记录读出来仍正确（旧版本）
        StoredRecord untouched = f.store().get("rec-000").orElseThrow();
        assertEquals(f.sourceVersion(), untouched.keyVersion());
        f.assertPlaintextUnchanged();
    }

    @Test
    void itemFailuresAreCollectedAndDoNotAbortTheBatch() {
        Fixture f = Fixture.setup(5);
        // 停用旧版本：旧密文无法解密，迁移逐条失败但不中断
        f.km().deactivate(f.sourceVersion());
        MigrationResult result = f.migration().migrateAll(null);
        log.info("场景: 源版本已停用时逐条失败被收集 -> processed={}, failed={}, reason[0]={}",
                result.processed(), result.failed(), result.failures().get(0).reason());
        assertEquals(0, result.processed());
        assertEquals(5, result.failed());
        assertEquals("KEY_DISABLED", result.failures().get(0).reason());
        assertFalse(result.failures().get(0).message().isBlank());
        // 失败信息不包含明文内容
        for (MigrationResult.ItemFailure failure : result.failures()) {
            assertFalse(failure.message().contains("plaintext-"),
                    "失败明细不得泄露明文内容");
        }
        // 旧密文保持不动、不回退（本来就没动），引用计数不变
        assertEquals(5, f.store().referenceCount(f.sourceVersion()));
    }

    @Test
    void migrationWithNoActiveKeyIsRejected() {
        KeyManager km = new KeyManager(32);
        CiphertextStore store = new CiphertextStore();
        BatchMigrationService migration = new BatchMigrationService(km, store);
        km.setReferenceChecker(store::isReferenced);
        store.save("x", km.encrypt("x".getBytes(StandardCharsets.UTF_8)));
        km.deactivate(km.activeVersion().orElseThrow());

        KeyOperationException ex = assertThrows(KeyOperationException.class,
                () -> migration.migrateAll(null));
        log.info("场景: 无活跃版本时迁移被拒 -> reason={}", ex.getReason());
        assertEquals(FailureReason.NO_ACTIVE_KEY, ex.getReason());
    }

    @Test
    void rotationDuringBatchFailsItemSafelyAndRerunConvergesToNewTarget() {
        // 3 条 v1 数据、目标 v2；处理第一条记录的"解密后、重加密前"窗口内轮换到 v3。
        Fixture f = Fixture.setup(3);
        f.migration().setBeforeReEncryptHook(new Runnable() {
            private boolean armed = true;

            @Override
            public void run() {
                if (armed) {
                    armed = false;
                    f.km().rotate(); // v2 -> v3
                }
            }
        });

        MigrationResult result = f.migration().migrateAll(null);
        log.info("场景: 批次中途轮换到 v3 -> failed={}, processed={}, targetVersion={}",
                result.failed(), result.processed(), result.targetVersion());
        // 第一条记录触发轮换后活跃版本变为 v3，与本批次锁定目标 v2 不符；
        // 本批次其余记录也一律安全失败——绝不允许同一批次里出现两个迁移方向
        assertEquals(3, result.failed(), "目标版本漂移后，本批次剩余记录必须全部安全失败");
        for (MigrationResult.ItemFailure failure : result.failures()) {
            assertEquals("ILLEGAL_STATE_TRANSITION", failure.reason());
        }
        assertEquals(0, result.processed());
        // 所有记录保持旧密文不动（v1），明文仍可解（v1 是 DECRYPT_ONLY），无一条写错方向
        f.assertPlaintextUnchanged();
        for (StoredRecord r : f.store().all()) {
            assertEquals(f.sourceVersion(), r.keyVersion(), "安全失败不得改写任何记录");
        }

        // 重跑：目标锁定 v3，全部记录收敛到 v3
        f.migration().setBeforeReEncryptHook(null);
        MigrationResult rerun = f.migration().migrateAll(null);
        log.info("场景: 轮换后重跑收敛 -> targetVersion={}, processed={}, skipped={}",
                rerun.targetVersion(), rerun.processed(), rerun.skipped());
        assertEquals(3, rerun.targetVersion());
        assertEquals(3, rerun.processed());
        assertEquals(0, rerun.skipped());
        f.assertPlaintextUnchanged();
    }

    @Test
    void cursorTargetingDifferentVersionIsRejected() {
        Fixture f = Fixture.setup(20);
        MigrationResult r1 = f.migration().migrateBatch(null, 5, null);
        // 再轮换一次：当前活跃版本变为 v3，旧游标绑定 v2
        int v3 = f.km().rotate();
        KeyOperationException ex = assertThrows(KeyOperationException.class,
                () -> f.migration().migrateBatch(null, 5, r1.nextCursor()));
        log.info("场景: 跨目标版本复用旧游标被拒 -> expectedTarget={}, reason={}", v3, ex.getReason());
        assertEquals(FailureReason.ILLEGAL_STATE_TRANSITION, ex.getReason());

        // 用全新迁移（无游标）可以朝新方向收敛
        MigrationResult fresh = f.migration().migrateAll(null);
        assertEquals(v3, fresh.targetVersion());
        List<Integer> versions = f.store().all().stream().map(StoredRecord::keyVersion).distinct().toList();
        assertEquals(List.of(v3), versions, "全新迁移后所有记录收敛到同一版本");
        f.assertPlaintextUnchanged();
    }
}
