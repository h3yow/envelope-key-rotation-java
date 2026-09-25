package com.github.h3yow.envelopekeyrotationjava.tests.crypto;

import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyStatus;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KeyManager 行为测试：每个用例打印密钥版本与判定依据。
 */
class KeyManagerTest {

    private static final Logger log = LoggerFactory.getLogger(KeyManagerTest.class);

    private static KeyOperationException expectReason(FailureReason expected, Runnable action) {
        KeyOperationException ex = assertThrows(KeyOperationException.class, action::run);
        log.info("assertion basis: expectedReason={}, actualReason={}, keyVersion={}",
                expected, ex.getReason(), ex.getKeyVersion());
        assertEquals(expected, ex.getReason());
        return ex;
    }

    @Test
    void encryptDecryptRoundTrip() {
        KeyManager km = new KeyManager();
        int version = km.activeVersion().orElseThrow();
        byte[] plaintext = "hello envelope".getBytes(StandardCharsets.UTF_8);
        String ct = km.encrypt(plaintext);
        byte[] back = km.decrypt(ct);
        log.info("roundTrip: keyVersion={}, ciphertext={}", version, ct);
        assertArrayEquals(plaintext, back);
        assertTrue(ct.startsWith("EK1." + version + "."), "ciphertext must carry key version");
    }

    @Test
    void historyCiphertextStillDecryptsAfterRotation() {
        KeyManager km = new KeyManager();
        int v1 = km.activeVersion().orElseThrow();
        String oldCt = km.encrypt("old-data".getBytes(StandardCharsets.UTF_8));

        int v2 = km.rotate();
        log.info("rotation: oldActive={}, newActive={}", v1, v2);
        assertEquals(v1 + 1, v2);

        // 历史密文仍可解密
        byte[] back = km.decrypt(oldCt);
        log.info("history decrypt ok: ciphertextVersion={}, currentActive={}", v1, v2);
        assertArrayEquals("old-data".getBytes(StandardCharsets.UTF_8), back);

        // 新加密使用最新版本
        String newCt = km.encrypt("new-data".getBytes(StandardCharsets.UTF_8));
        assertTrue(newCt.startsWith("EK1." + v2 + "."), "new encryption must use latest version");
        log.info("new encrypt uses latest version: keyVersion={}", v2);
    }

    @Test
    void burstRotationKeepsStateConsistent() throws Exception {
        KeyManager km = new KeyManager();
        int initial = km.activeVersion().orElseThrow();
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch gate = new CountDownLatch(1);
        List<Future<Integer>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                gate.await();
                return km.rotate();
            }));
        }
        gate.countDown();
        Set<Integer> results = ConcurrentHashMap.newKeySet();
        for (Future<Integer> f : futures) {
            results.add(f.get(10, TimeUnit.SECONDS));
        }
        pool.shutdown();

        int active = km.activeVersion().orElseThrow();
        log.info("burst rotate: distinctResults={}, activeVersion={}", results, active);
        // 一致性：恰好一个活跃版本，且为所有结果中的最大值
        long activeCount = km.listVersions().stream().filter(kv -> kv.getStatus() == KeyStatus.ACTIVE).count();
        assertEquals(1, activeCount, "exactly one active version allowed");
        assertEquals(active, results.stream().mapToInt(Integer::intValue).max().orElseThrow(),
                "active version must be the max of all rotation results");
        // 无部分轮换：每个返回的版本都真实存在，版本号连续无空洞
        assertEquals(initial + results.size(), km.listVersions().size());
        for (int v : results) {
            int finalV = v;
            assertTrue(km.listVersions().stream().anyMatch(kv -> kv.getVersion() == finalV),
                    "every returned version must exist");
        }
        // 轮换后读写结论一致
        byte[] msg = "after-burst".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(msg, km.decrypt(km.encrypt(msg)));
    }

    @Test
    void concurrentEncryptDecryptDuringRotationIsConsistent() throws Exception {
        KeyManager km = new KeyManager();
        int threads = 8;
        int iterations = 50;
        ExecutorService pool = Executors.newFixedThreadPool(threads + 1);
        CountDownLatch gate = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            int seed = i;
            futures.add(pool.submit(() -> {
                gate.await();
                for (int j = 0; j < iterations; j++) {
                    byte[] msg = ("msg-" + seed + "-" + j).getBytes(StandardCharsets.UTF_8);
                    String ct = km.encrypt(msg);
                    assertArrayEquals(msg, km.decrypt(ct));
                }
                return null;
            }));
        }
        futures.add(pool.submit(() -> {
            gate.await();
            for (int j = 0; j < 5; j++) {
                km.rotate();
            }
            return null;
        }));
        gate.countDown();
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();
        log.info("read/write during rotation consistent: finalActive={}", km.activeVersion());
    }

    @Test
    void tamperedPayloadRejected() {
        KeyManager km = new KeyManager();
        String ct = km.encrypt("sensitive".getBytes(StandardCharsets.UTF_8));
        String[] parts = ct.split("\\.");
        byte[] payload = Base64.getUrlDecoder().decode(parts[2]);
        payload[payload.length - 1] ^= 0x01; // 翻转最后一个字节
        String tampered = parts[0] + "." + parts[1] + "."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
        int version = km.activeVersion().orElseThrow();
        log.info("tamper test: keyVersion={}, flipped last payload byte", version);
        expectReason(FailureReason.CIPHERTEXT_TAMPERED, () -> km.decrypt(tampered));
    }

    @Test
    void tamperedVersionFieldRejected() {
        KeyManager km = new KeyManager();
        km.rotate(); // 现有版本 1、2
        String ct = km.encrypt("sensitive".getBytes(StandardCharsets.UTF_8));
        String[] parts = ct.split("\\.");
        // 把版本字段从 2 改成 1：AAD 绑定版本号，认证必失败，且绝不回退用 v1 解密成功
        String swapped = parts[0] + ".1." + parts[2];
        log.info("version-swap test: claimedVersion=1, actualVersion=2");
        expectReason(FailureReason.CIPHERTEXT_TAMPERED, () -> km.decrypt(swapped));
    }

    @Test
    void missingOrMalformedVersionRejected() {
        KeyManager km = new KeyManager();
        String ct = km.encrypt("x".getBytes(StandardCharsets.UTF_8));
        String payload = ct.split("\\.")[2];

        expectReason(FailureReason.VERSION_MISSING, () -> km.decrypt("EK1.." + payload));
        expectReason(FailureReason.VERSION_MISSING, () -> km.decrypt("EK1.abc." + payload));
        expectReason(FailureReason.CIPHERTEXT_MALFORMED, () -> km.decrypt("not-a-ciphertext"));
        expectReason(FailureReason.CIPHERTEXT_MALFORMED, () -> km.decrypt("EK1.1.!!!not-base64!!!"));
        expectReason(FailureReason.CIPHERTEXT_MALFORMED, () -> km.decrypt(""));
        log.info("malformed inputs rejected with distinguishable reasons");
    }

    @Test
    void unknownVersionRejectedWithoutFallback() {
        KeyManager km = new KeyManager();
        String ct = km.encrypt("x".getBytes(StandardCharsets.UTF_8));
        String forged = "EK1.999." + ct.split("\\.")[2];
        log.info("unknown version test: claimedVersion=999, existingVersions={}",
                km.listVersions().stream().map(kv -> kv.getVersion()).toList());
        expectReason(FailureReason.KEY_NOT_FOUND, () -> km.decrypt(forged));
    }

    @Test
    void disabledKeyRejectsEncryptAndDecrypt() {
        KeyManager km = new KeyManager();
        int v1 = km.activeVersion().orElseThrow();
        String ct = km.encrypt("before-disable".getBytes(StandardCharsets.UTF_8));

        km.deactivate(v1);
        log.info("deactivated: keyVersion={}, status={}", v1, km.listVersions().get(0).getStatus());

        // 历史密文拒绝解密，原因可区分
        expectReason(FailureReason.KEY_DISABLED, () -> km.decrypt(ct));
        // 无活跃密钥，加密被拒绝
        expectReason(FailureReason.NO_ACTIVE_KEY, () -> km.encrypt("y".getBytes(StandardCharsets.UTF_8)));

        // 轮换出新版本后加密恢复，但旧密文仍因停用被拒绝（不回退）
        int v2 = km.rotate();
        log.info("rotated after disable: newActive={}, oldVersion={} still DISABLED", v2, v1);
        assertDoesNotThrow(() -> km.encrypt("z".getBytes(StandardCharsets.UTF_8)));
        expectReason(FailureReason.KEY_DISABLED, () -> km.decrypt(ct));
    }

    @Test
    void destroyIsIrreversibleAndClearsMaterial() {
        KeyManager km = new KeyManager();
        int v1 = km.activeVersion().orElseThrow();
        String ct = km.encrypt("doomed".getBytes(StandardCharsets.UTF_8));

        // 非法迁移：ACTIVE 不能直接销毁
        expectReason(FailureReason.ILLEGAL_STATE_TRANSITION, () -> km.destroy(v1));

        km.deactivate(v1);
        km.destroy(v1);
        log.info("destroyed: keyVersion={}, status={}", v1, km.listVersions().get(0).getStatus());

        // 销毁后解密拒绝，原因与停用可区分
        expectReason(FailureReason.KEY_DESTROYED, () -> km.decrypt(ct));
        // 不可逆：不能再次销毁、不能重新停用
        expectReason(FailureReason.ILLEGAL_STATE_TRANSITION, () -> km.destroy(v1));
        expectReason(FailureReason.ILLEGAL_STATE_TRANSITION, () -> km.deactivate(v1));
        // 密钥材料已清零
        assertTrue(km.listVersions().get(0).isMaterialDestroyed(), "destroyed key material must be cleared");
    }

    @Test
    void operationsOnUnknownVersionRejected() {
        KeyManager km = new KeyManager();
        expectReason(FailureReason.KEY_NOT_FOUND, () -> km.deactivate(42));
        expectReason(FailureReason.KEY_NOT_FOUND, () -> km.destroy(42));
        log.info("lifecycle ops on unknown version rejected: reason={}", FailureReason.KEY_NOT_FOUND);
    }

    @Test
    void keyMaterialNeverLeaksIntoExceptionOrToString() {
        KeyManager km = new KeyManager();
        int v1 = km.activeVersion().orElseThrow();
        km.deactivate(v1);
        KeyOperationException ex = expectReason(FailureReason.KEY_DISABLED,
                () -> km.decrypt("EK1." + v1 + "." + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(new byte[100])));
        String view = km.listVersions().get(0).toString();
        log.info("leak check: exceptionMessage={}, keyVersionToString={}", ex.getMessage(), view);
        assertFalse(view.contains("keyMaterial"), "toString must not contain key material");
        assertFalse(ex.getMessage().matches(".*[A-Za-z0-9+/]{32,}.*"),
                "exception message must not contain base64-like key material");
    }
}
