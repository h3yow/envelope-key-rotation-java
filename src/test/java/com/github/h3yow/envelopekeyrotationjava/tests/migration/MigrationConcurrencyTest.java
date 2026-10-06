package com.github.h3yow.envelopekeyrotationjava.tests.migration;

import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyStatus;
import com.github.h3yow.envelopekeyrotationjava.migration.BatchMigrationService;
import com.github.h3yow.envelopekeyrotationjava.migration.MigrationResult;
import com.github.h3yow.envelopekeyrotationjava.storage.CiphertextStore;
import com.github.h3yow.envelopekeyrotationjava.storage.StoredRecord;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 迁移并发测试：多发起人收敛、与在线读写并存时一致性、与销毁并发时的边界。
 */
class MigrationConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(MigrationConcurrencyTest.class);

    private record System(KeyManager km, CiphertextStore store, BatchMigrationService migration) {
        static System boot(int maxVersions) {
            KeyManager km = new KeyManager(maxVersions);
            CiphertextStore store = new CiphertextStore();
            BatchMigrationService migration = new BatchMigrationService(km, store);
            km.setReferenceChecker(store::isReferenced);
            return new System(km, store, migration);
        }
    }

    private System seedOldRecords(int n) {
        System sys = System.boot(32);
        for (int i = 0; i < n; i++) {
            String id = "old-" + String.format("%04d", i);
            sys.store().save(id, sys.km().encrypt(
                    ("value-" + i).getBytes(StandardCharsets.UTF_8)));
        }
        return sys;
    }

    @Test
    void concurrentMigrationCallsConvergeToSingleResult() throws Exception {
        // 100 条老数据迁到 v2，8 个线程同时对同一批数据发起全量迁移
        System sys = seedOldRecords(100);
        int target = sys.km().rotate();
        int callers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        CountDownLatch gate = new CountDownLatch(1);
        List<Future<MigrationResult>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < callers; i++) {
            futures.add(pool.submit(() -> {
                gate.await();
                return sys.migration().migrateAll(null);
            }));
        }
        gate.countDown();
        int sumProcessed = 0;
        for (Future<MigrationResult> f : futures) {
            MigrationResult r = f.get(30, TimeUnit.SECONDS);
            assertEquals(target, r.targetVersion(), "所有并发迁移必须指向同一个目标版本");
            sumProcessed += r.processed();
        }
        pool.shutdown();

        log.info("场景: {} 人同时迁移同一批数据 -> 总实际重加密次数={}（应=100），目标版本统一为 {}",
                callers, sumProcessed, target);
        assertEquals(100, sumProcessed, "单飞+CAS 下每条记录恰好被重加密一次");
        assertEquals(0, sys.store().referenceCount(1), "旧版本引用必须清零");
        assertEquals(100, sys.store().referenceCount(target));
        for (StoredRecord r : sys.store().all()) {
            assertEquals(target, r.keyVersion());
            assertEquals("value-" + Integer.parseInt(r.id().substring(4)),
                    new String(sys.km().decrypt(r.ciphertext()), StandardCharsets.UTF_8));
        }
    }

    @Test
    void migrationConcurrentWithOnlineWritesAndReadsKeepsReadsCorrect() throws Exception {
        // 初始 200 条 v1 老数据；迁移进行期间，多个线程持续新增/覆盖写入（走当前活跃版本），
        // 同时持续读取全部记录；任何一次读取都必须拿到正确明文，且版本结论前后一致。
        System sys = seedOldRecords(200);
        int target = sys.km().rotate();

        ExecutorService pool = Executors.newFixedThreadPool(6);
        java.util.concurrent.atomic.AtomicBoolean running =
                new java.util.concurrent.atomic.AtomicBoolean(true);
        AtomicInteger writes = new AtomicInteger();
        Map<String, String> errors = new ConcurrentHashMap<>();

        // 在线写入线程：新增 new-* 记录 + 覆盖部分 old-* 记录，明文已知
        for (int w = 0; w < 3; w++) {
            int seed = w;
            pool.submit(() -> {
                try {
                    while (running.get()) {
                        int i = writes.incrementAndGet();
                        // 一半概率写新记录，一半概率覆盖老记录
                        if (i % 2 == 0) {
                            String id = "new-" + seed + "-" + i;
                            String value = "online-" + id;
                            sys.store().save(id, sys.km().encrypt(value.getBytes(StandardCharsets.UTF_8)));
                        } else {
                            int idx = i % 200;
                            String id = "old-" + String.format("%04d", idx);
                            String value = "overwritten-" + idx + "-" + i;
                            sys.store().save(id, sys.km().encrypt(value.getBytes(StandardCharsets.UTF_8)));
                        }
                        Thread.sleep(1);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (Exception e) {
                    errors.put("writer-" + seed, e.toString());
                }
            });
        }
        // 在线读取线程：持续校验全部记录（读密文自描述版本必须等于记录版本，明文非空），
        // 每轮让出 CPU，保证迁移线程能拿到锁推进
        for (int r = 0; r < 2; r++) {
            pool.submit(() -> {
                try {
                    while (running.get()) {
                        for (StoredRecord rec : sys.store().all()) {
                            byte[] pt = sys.km().decrypt(rec.ciphertext());
                            int ctVersion = com.github.h3yow.envelopekeyrotationjava.crypto.Ciphertext
                                    .parse(rec.ciphertext()).keyVersion();
                            if (ctVersion != rec.keyVersion()) {
                                errors.put("reader-version-mismatch-" + rec.id(),
                                        ctVersion + " != " + rec.keyVersion());
                            }
                            if (pt.length == 0) {
                                errors.put("reader-empty-" + rec.id(), "empty plaintext");
                            }
                        }
                        Thread.sleep(2);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (Exception e) {
                    errors.put("reader", e.toString());
                }
            });
        }

        // 迁移者本身也在线程池中：小分片多轮，最大化与读写的交错
        Future<?> migrator = pool.submit(() -> {
            String cursor = null;
            do {
                MigrationResult result = sys.migration().migrateBatch(null, 17, cursor);
                cursor = result.nextCursor();
            } while (cursor != null);
            return null;
        });
        migrator.get(30, TimeUnit.SECONDS);
        running.set(false);
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        log.info("场景: 迁移与在线写入/读取并存 -> 并发写入次数={}, 读取异常数={}, 最终 v1 引用={}, v{} 引用={}",
                writes.get(), errors.size(), sys.store().referenceCount(1),
                target, sys.store().referenceCount(target));
        assertTrue(errors.isEmpty(), "迁移期间不允许出现读取失败或版本不一致: " + errors);
        // 收敛：再跑一遍迁移，没有任何 v1 残留需要处理（被在线覆盖的 old-* 也已是目标版本）
        MigrationResult sweep = sys.migration().migrateAll(null);
        assertEquals(0, sweep.processed());
        assertEquals(0, sys.store().referenceCount(1), "最终不得残留旧版本引用");
        // 终态一致性：所有记录都能正确解密
        for (StoredRecord rec : sys.store().all()) {
            byte[] pt = sys.km().decrypt(rec.ciphertext());
            assertNotNull(pt);
            assertFalse(pt.length == 0);
        }
    }

    @Test
    void destroyRacesWithMigrationAndNeitherCorruptsNorLosesData() throws Exception {
        // 30 条 v1 数据，v2 为活跃，v1 处于 DECRYPT_ONLY（仍可解密，迁移得以进行）。
        // 迁移期间另一个线程反复尝试销毁 v1：只要还有引用，销毁必须先命中引用检查而被拒，
        // 绝不会因状态原因或时序漏洞提前销毁。迁移结束后，主线程停用再销毁，一次成功。
        System sys = seedOldRecords(30);
        int target = sys.km().rotate();

        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch gate = new CountDownLatch(1);
        AtomicInteger rejectedWhileReferenced = new AtomicInteger();
        List<FailureReason> unexpected = new java.util.concurrent.CopyOnWriteArrayList<>();
        java.util.concurrent.atomic.AtomicBoolean migrationDone =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        Future<?> destroyer = pool.submit(() -> {
            gate.await();
            while (!migrationDone.get()) {
                try {
                    sys.km().destroy(1);
                    // 理论上迁移未完成不可能走到这里；若发生说明引用检查失效
                    unexpected.add(null);
                } catch (KeyOperationException e) {
                    if (e.getReason() == FailureReason.KEY_STILL_REFERENCED) {
                        rejectedWhileReferenced.incrementAndGet();
                    } else if (e.getReason() == FailureReason.ILLEGAL_STATE_TRANSITION
                            && !sys.store().isReferenced(1)) {
                        // 合理窗口：迁移已完成、主线程已把 v1 停用，销毁必须先停用后销毁
                    } else {
                        unexpected.add(e.getReason());
                    }
                }
            }
            return null;
        });
        Future<MigrationResult> migrator = pool.submit(() -> {
            gate.await();
            return sys.migration().migrateAll(null);
        });
        gate.countDown();
        MigrationResult result = migrator.get(30, TimeUnit.SECONDS);
        migrationDone.set(true);
        destroyer.get(10, TimeUnit.SECONDS);
        pool.shutdown();

        // 迁移期间看到的只允许是 KEY_STILL_REFERENCED
        log.info("场景: 迁移与销毁并发 -> 因仍被引用而拒绝销毁的次数={}, 本次迁移 processed={}",
                rejectedWhileReferenced.get(), result.processed());
        assertTrue(rejectedWhileReferenced.get() > 0, "迁移完成前必须出现过因引用而拒绝销毁");
        assertTrue(unexpected.isEmpty(),
                "迁移进行中销毁失败原因只能是 KEY_STILL_REFERENCED: " + unexpected);

        // 引用清零后：停用再销毁成功，且与 KEY_STILL_REFERENCED 的边界清晰可区分
        sys.km().deactivate(1);
        sys.km().destroy(1);
        assertEquals(KeyStatus.DESTROYED, sys.km().listVersions().get(0).getStatus());
        log.info("场景: 引用清零后停用+销毁 -> v1 status={}, materialDestroyed={}",
                sys.km().listVersions().get(0).getStatus(),
                sys.km().listVersions().get(0).isMaterialDestroyed());

        // 所有数据都已在 v2，明文完好
        for (StoredRecord r : sys.store().all()) {
            assertEquals(target, r.keyVersion());
            assertEquals("value-" + Integer.parseInt(r.id().substring(4)),
                    new String(sys.km().decrypt(r.ciphertext()), StandardCharsets.UTF_8));
        }
    }
}
