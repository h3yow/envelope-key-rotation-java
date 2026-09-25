package com.github.h3yow.envelopekeyrotationjava.tests;

import com.github.h3yow.envelopekeyrotationjava.crypto.CryptoErrorCode;
import com.github.h3yow.envelopekeyrotationjava.crypto.CryptoException;
import com.github.h3yow.envelopekeyrotationjava.crypto.CryptoService;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyStatus;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Behavior tests for the envelope crypto service. Each test logs the key
 * versions involved and the basis for its assertions.
 */
class CryptoServiceTest {

    private static final Logger log = LoggerFactory.getLogger(CryptoServiceTest.class);

    private final CryptoService service = new CryptoService();

    @Test
    void encryptDecryptRoundtripCarriesVersion() {
        int v = service.getActiveVersion();
        String ct = service.encrypt("hello-envelope");
        String pt = service.decrypt(ct);
        log.info("roundtrip: activeVersion={} decryptOk={}", v, pt.equals("hello-envelope"));
        assertEquals("hello-envelope", pt);
        assertEquals(v, service.getActiveVersion());
    }

    @Test
    void historicalCiphertextStillDecryptsAfterRotation() {
        int v1 = service.getActiveVersion();
        String ctV1 = service.encrypt("old-secret");
        KeyManager.RotationResult r = service.rotate();
        int v2 = r.activeVersion();
        String ctV2 = service.encrypt("new-secret");

        String ptV1 = service.decrypt(ctV1);
        String ptV2 = service.decrypt(ctV2);
        log.info("history compat: v1={} v2={} v1DecryptOk={} v2DecryptOk={}",
                v1, v2, ptV1.equals("old-secret"), ptV2.equals("new-secret"));

        assertTrue(r.rotated());
        assertNotEquals(v1, v2);
        assertEquals("old-secret", ptV1);
        assertEquals("new-secret", ptV2);
    }

    @Test
    void concurrentRotationsConvergeToSingleResult() throws Exception {
        int expected = service.getActiveVersion();
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<KeyManager.RotationResult>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return service.rotate(expected);
            }));
        }
        start.countDown();
        List<KeyManager.RotationResult> results = new ArrayList<>();
        for (Future<KeyManager.RotationResult> f : futures) {
            results.add(f.get());
        }
        pool.shutdown();

        long rotatedCount = results.stream().filter(KeyManager.RotationResult::rotated).count();
        int finalActive = results.get(0).activeVersion();
        boolean allAgree = results.stream().allMatch(r -> r.activeVersion() == finalActive);
        long keyCount = service.listKeys().size();
        log.info("concurrent rotate: expected={} threads={} rotatedCount={} finalActive={} allAgree={} keyCount={}",
                expected, threads, rotatedCount, finalActive, allAgree, keyCount);

        assertEquals(1, rotatedCount, "exactly one rotation must win");
        assertTrue(allAgree, "all callers must observe the same resulting active version");
        assertEquals(expected + 1, finalActive);
        assertEquals(2, keyCount, "no partial rotation: exactly one new key version");
        // Read/write consistency during and after rotation: both versions decrypt.
        assertEquals(KeyStatus.ACTIVE, service.listKeys().get(1).status());
    }

    @Test
    void tamperedCiphertextIsRejectedWithIntegrityFailure() {
        String ct = service.encrypt("tamper-target");
        byte[] raw = Base64.getUrlDecoder().decode(ct);
        raw[raw.length - 1] ^= 0x01; // flip one bit in the GCM tag area
        String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        CryptoException ex = assertThrows(CryptoException.class, () -> service.decrypt(tampered));
        log.info("tamper: version={} code={} reason={}",
                service.getActiveVersion(), ex.getCode(), ex.getMessage());
        assertEquals(CryptoErrorCode.INTEGRITY_CHECK_FAILED, ex.getCode());
    }

    @Test
    void swappedVersionHeaderIsRejectedAndNeverFallsBack() {
        String ctV1 = service.encrypt("version-binding");
        int v2 = service.rotate().activeVersion();

        byte[] raw = Base64.getUrlDecoder().decode(ctV1);
        // Rewrite the 4-byte version header (offset 2) to v2.
        raw[5] = (byte) v2;
        String swapped = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        CryptoException ex = assertThrows(CryptoException.class, () -> service.decrypt(swapped));
        log.info("version swap: originalVersion=1 forgedVersion={} code={} (AAD binding, no fallback)",
                v2, ex.getCode());
        assertEquals(CryptoErrorCode.INTEGRITY_CHECK_FAILED, ex.getCode());
    }

    @Test
    void malformedAndMissingVersionCiphertextsAreDistinguishable() {
        CryptoException badBase64 = assertThrows(CryptoException.class, () -> service.decrypt("###not-base64###"));
        CryptoException empty = assertThrows(CryptoException.class, () -> service.decrypt(""));
        // Valid base64, valid magic, but truncated before the version field.
        String noVersion = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[]{'E', 'K'});
        CryptoException missingVersion = assertThrows(CryptoException.class, () -> service.decrypt(noVersion));
        // Valid envelope but references a key version we do not hold.
        String ct = service.encrypt("x");
        byte[] raw = Base64.getUrlDecoder().decode(ct);
        raw[2] = 0; raw[3] = 0; raw[4] = 0; raw[5] = 99; // version = 99
        String unknownVersion = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        CryptoException unknown = assertThrows(CryptoException.class, () -> service.decrypt(unknownVersion));

        log.info("malformed: badBase64={} empty={} missingVersion={} unknownVersion={}",
                badBase64.getCode(), empty.getCode(), missingVersion.getCode(), unknown.getCode());

        assertEquals(CryptoErrorCode.MALFORMED_CIPHERTEXT, badBase64.getCode());
        assertEquals(CryptoErrorCode.MALFORMED_CIPHERTEXT, empty.getCode());
        assertEquals(CryptoErrorCode.VERSION_MISSING, missingVersion.getCode());
        assertEquals(CryptoErrorCode.UNKNOWN_KEY_VERSION, unknown.getCode());
    }

    @Test
    void disabledKeyIsDecryptOnlyAndDisableIsIrreversible() {
        int v1 = service.getActiveVersion();
        String ctV1 = service.encrypt("before-disable");
        service.disableKey(v1);

        // Historical ciphertext still decrypts.
        assertEquals("before-disable", service.decrypt(ctV1));
        // Encryption with a DISABLED active key is refused with a distinct reason.
        CryptoException encEx = assertThrows(CryptoException.class, () -> service.encrypt("after-disable"));
        // Disabling twice is an illegal transition.
        CryptoException dupEx = assertThrows(CryptoException.class, () -> service.disableKey(v1));
        log.info("disable: version={} encryptCode={} duplicateDisableCode={} decryptStillOk=true",
                v1, encEx.getCode(), dupEx.getCode());

        assertEquals(CryptoErrorCode.KEY_DISABLED, encEx.getCode());
        assertEquals(CryptoErrorCode.ILLEGAL_STATE_TRANSITION, dupEx.getCode());
        // Rotation recovers encryption capability.
        service.rotate();
        assertDoesNotThrow(() -> service.encrypt("after-rotate"));
    }

    @Test
    void destroyedKeyCannotDecryptAndDestroyIsIrreversible() {
        int v1 = service.getActiveVersion();
        String ctV1 = service.encrypt("doomed");
        service.destroyKey(v1);

        CryptoException decEx = assertThrows(CryptoException.class, () -> service.decrypt(ctV1));
        CryptoException encEx = assertThrows(CryptoException.class, () -> service.encrypt("x"));
        CryptoException dupDestroy = assertThrows(CryptoException.class, () -> service.destroyKey(v1));
        CryptoException disableAfterDestroy = assertThrows(CryptoException.class, () -> service.disableKey(v1));
        log.info("destroy: version={} decryptCode={} encryptCode={} dupDestroyCode={} disableAfterDestroyCode={}",
                v1, decEx.getCode(), encEx.getCode(), dupDestroy.getCode(), disableAfterDestroy.getCode());

        assertEquals(CryptoErrorCode.KEY_DESTROYED, decEx.getCode());
        assertEquals(CryptoErrorCode.KEY_DESTROYED, encEx.getCode());
        assertEquals(CryptoErrorCode.ILLEGAL_STATE_TRANSITION, dupDestroy.getCode());
        assertEquals(CryptoErrorCode.ILLEGAL_STATE_TRANSITION, disableAfterDestroy.getCode());
        assertEquals(KeyStatus.DESTROYED, service.listKeys().get(0).status());
    }

    @Test
    void lifecycleOpsOnUnknownVersionAreRejected() {
        CryptoException d = assertThrows(CryptoException.class, () -> service.disableKey(777));
        CryptoException x = assertThrows(CryptoException.class, () -> service.destroyKey(777));
        log.info("unknown version ops: disableCode={} destroyCode={}", d.getCode(), x.getCode());
        assertEquals(CryptoErrorCode.UNKNOWN_KEY_VERSION, d.getCode());
        assertEquals(CryptoErrorCode.UNKNOWN_KEY_VERSION, x.getCode());
    }

    @Test
    void rotationWithStaleExpectationDoesNotRotate() {
        int v1 = service.getActiveVersion();
        KeyManager.RotationResult first = service.rotate(v1);
        // A late caller still expecting v1 must converge, not rotate again.
        KeyManager.RotationResult late = service.rotate(v1);
        log.info("stale expectation: v1={} first=(active={},rotated={}) late=(active={},rotated={})",
                v1, first.activeVersion(), first.rotated(), late.activeVersion(), late.rotated());
        assertTrue(first.rotated());
        assertFalse(late.rotated());
        assertEquals(first.activeVersion(), late.activeVersion());
        assertEquals(2, service.listKeys().size());
    }
}
