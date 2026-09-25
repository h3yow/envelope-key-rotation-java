package com.github.h3yow.envelopekeyrotationjava.crypto;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发轮换的确定性测试：借助包级测试钩子控制线程交错，
 * 验证真实重叠的轮换请求收敛为唯一结果。
 */
class KeyManagerConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(KeyManagerConcurrencyTest.class);

    @Test
    void overlappingRotationsConvergeToUniqueResult() throws Exception {
        KeyManager km = new KeyManager();
        int initial = km.activeVersion().orElseThrow();

        CountDownLatch hookEntered = new CountDownLatch(1);
        CountDownLatch hookRelease = new CountDownLatch(1);
        km.setRotationHook(() -> {
            hookEntered.countDown();
            try {
                hookRelease.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        ExecutorService pool = Executors.newFixedThreadPool(3);
        try {
            // 线程 A：进入轮换临界区并被钩子阻塞
            Future<Integer> a = pool.submit(km::rotate);
            assertTrue(hookEntered.await(5, TimeUnit.SECONDS), "leader must enter rotation critical section");

            // 线程 B、C：在 A 持有锁期间发起轮换（真实重叠）
            AtomicInteger started = new AtomicInteger();
            Runnable joiner = () -> started.incrementAndGet();
            Future<Integer> b = pool.submit(() -> { joiner.run(); return km.rotate(); });
            Future<Integer> c = pool.submit(() -> { joiner.run(); return km.rotate(); });
            while (started.get() < 2) {
                Thread.sleep(10);
            }
            // B、C 只能阻塞在轮换锁上（A 仍持有锁），给予充分的调度余量
            Thread.sleep(300);

            // 放行 A 完成轮换
            hookRelease.countDown();
            int ra = a.get(5, TimeUnit.SECONDS);
            int rb = b.get(5, TimeUnit.SECONDS);
            int rc = c.get(5, TimeUnit.SECONDS);
            log.info("overlapping rotations converged: results=[{}, {}, {}], activeVersion={}",
                    ra, rb, rc, km.activeVersion());

            // 收敛为唯一结果
            assertEquals(ra, rb, "overlapping rotations must converge");
            assertEquals(ra, rc, "overlapping rotations must converge");
            // 恰好产生一个新版本
            assertEquals(initial + 1, ra);
            assertEquals(initial + 1, km.listVersions().size(), "exactly one new version created");
            // 唯一活跃版本
            long activeCount = km.listVersions().stream()
                    .filter(kv -> kv.getStatus() == KeyStatus.ACTIVE).count();
            assertEquals(1, activeCount);
            assertEquals(ra, km.activeVersion().orElseThrow());
        } finally {
            km.setRotationHook(null);
            pool.shutdownNow();
        }
    }

    @Test
    void sequentialRotationsCreateDistinctVersions() {
        KeyManager km = new KeyManager();
        int v1 = km.activeVersion().orElseThrow();
        int v2 = km.rotate();
        int v3 = km.rotate();
        log.info("sequential rotations: {} -> {} -> {}", v1, v2, v3);
        assertEquals(v1 + 1, v2);
        assertEquals(v2 + 1, v3);
        assertEquals(v3, km.activeVersion().orElseThrow());
        List<Integer> all = km.listVersions().stream().map(KeyVersion::getVersion).toList();
        assertEquals(List.of(v1, v2, v3), all, "sequential rotations must create distinct versions");
    }
}
