package com.github.h3yow.envelopekeyrotationjava.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 进程内信封加密密钥管理器：模拟密钥生命周期（创建、轮换、停用、销毁）。
 *
 * <p>语义约定：</p>
 * <ul>
 *   <li>加密始终使用当前活跃版本；解密按密文携带的版本寻址，绝不回退到其他密钥。</li>
 *   <li>并发轮换收敛为唯一结果：同一时刻只产生一个新版本，所有并发请求得到相同结论。</li>
 *   <li>停用/销毁不可逆；销毁后密钥材料清零。</li>
 *   <li>密钥材料不出现在日志、异常或返回值中。</li>
 * </ul>
 *
 * <p>信封结构：每条消息生成随机 DEK，用版本对应的 KEK 以 AES-GCM 包裹；
 * payload 布局 = wrapIv(12B) | wrappedDek(48B) | dataIv(12B) | dataCiphertext+tag。
 * 两段 GCM 的 AAD 均绑定版本号，篡改版本字段会导致认证失败。</p>
 */
@Service
public class KeyManager {

    private static final Logger log = LoggerFactory.getLogger(KeyManager.class);

    private static final int WRAP_IV_OFF = 0;
    private static final int WRAPPED_DEK_OFF = WRAP_IV_OFF + AesGcmCipher.IV_BYTES;
    private static final int WRAPPED_DEK_LEN = AesGcmCipher.KEY_BYTES + AesGcmCipher.TAG_BITS / 8;
    private static final int DATA_IV_OFF = WRAPPED_DEK_OFF + WRAPPED_DEK_LEN;
    private static final int DATA_CT_OFF = DATA_IV_OFF + AesGcmCipher.IV_BYTES;
    private static final int MIN_PAYLOAD_LEN = DATA_CT_OFF + AesGcmCipher.TAG_BITS / 8;

    private final ConcurrentHashMap<Integer, KeyVersion> versions = new ConcurrentHashMap<>();
    private final Object rotationLock = new Object();

    private volatile KeyVersion active;
    private volatile long rotationEpoch;

    /** 测试钩子：在轮换临界区内、新版本创建前执行。仅用于并发测试，生产环境不得设置。 */
    private volatile Runnable rotationHook;

    public KeyManager() {
        KeyVersion initial = new KeyVersion(1, AesGcmCipher.generateKey(), Instant.now());
        versions.put(1, initial);
        active = initial;
        log.info("key manager initialized, activeVersion={}", 1);
    }

    /** 使用当前活跃版本加密，返回携带版本信息的密文。 */
    public String encrypt(byte[] plaintext) {
        if (plaintext == null) {
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED, "plaintext must not be null");
        }
        KeyVersion key = active;
        if (key == null || key.getStatus() != KeyStatus.ACTIVE) {
            log.warn("encrypt rejected: no active key, reason={}", FailureReason.NO_ACTIVE_KEY);
            throw new KeyOperationException(FailureReason.NO_ACTIVE_KEY, "no active key version available for encryption");
        }
        int version = key.getVersion();
        byte[] aad = aad(version);
        byte[] dek = AesGcmCipher.generateKey();
        try {
            byte[] wrapIv = AesGcmCipher.randomIv();
            byte[] wrappedDek = AesGcmCipher.encrypt(key.keyMaterial(), wrapIv, dek, aad);
            byte[] dataIv = AesGcmCipher.randomIv();
            byte[] dataCt = AesGcmCipher.encrypt(dek, dataIv, plaintext, aad);

            byte[] payload = ByteBuffer.allocate(DATA_CT_OFF + dataCt.length)
                    .put(wrapIv).put(wrappedDek).put(dataIv).put(dataCt).array();
            String encoded = new Ciphertext(version, payload).encode();
            log.info("encrypt ok: keyVersion={}, plaintextBytes={}", version, plaintext.length);
            return encoded;
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    /** 按密文携带的版本解密；任何失败均抛出带可区分原因的异常，绝不回退到其他密钥。 */
    public byte[] decrypt(String encodedCiphertext) {
        Ciphertext ct = Ciphertext.parse(encodedCiphertext);
        int version = ct.keyVersion();
        byte[] payload = ct.payload();
        if (payload.length < MIN_PAYLOAD_LEN) {
            log.warn("decrypt rejected: keyVersion={}, reason={}", version, FailureReason.CIPHERTEXT_MALFORMED);
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED, version,
                    "ciphertext payload too short");
        }
        KeyVersion key = versions.get(version);
        if (key == null) {
            log.warn("decrypt rejected: keyVersion={}, reason={}", version, FailureReason.KEY_NOT_FOUND);
            throw new KeyOperationException(FailureReason.KEY_NOT_FOUND, version,
                    "key version " + version + " does not exist");
        }
        switch (key.getStatus()) {
            case DISABLED -> {
                log.warn("decrypt rejected: keyVersion={}, reason={}", version, FailureReason.KEY_DISABLED);
                throw new KeyOperationException(FailureReason.KEY_DISABLED, version,
                        "key version " + version + " is disabled");
            }
            case DESTROYED -> {
                log.warn("decrypt rejected: keyVersion={}, reason={}", version, FailureReason.KEY_DESTROYED);
                throw new KeyOperationException(FailureReason.KEY_DESTROYED, version,
                        "key version " + version + " is destroyed");
            }
            case ACTIVE, DECRYPT_ONLY -> {
                // 允许解密：活跃版本与仅解密版本均可还原历史密文
            }
        }
        byte[] aad = aad(version);
        byte[] wrapIv = Arrays.copyOfRange(payload, WRAP_IV_OFF, WRAPPED_DEK_OFF);
        byte[] wrappedDek = Arrays.copyOfRange(payload, WRAPPED_DEK_OFF, DATA_IV_OFF);
        byte[] dataIv = Arrays.copyOfRange(payload, DATA_IV_OFF, DATA_CT_OFF);
        byte[] dataCt = Arrays.copyOfRange(payload, DATA_CT_OFF, payload.length);

        byte[] dek = AesGcmCipher.decrypt(key.keyMaterial(), wrapIv, wrappedDek, aad);
        try {
            byte[] plaintext = AesGcmCipher.decrypt(dek, dataIv, dataCt, aad);
            log.info("decrypt ok: keyVersion={}, plaintextBytes={}", version, plaintext.length);
            return plaintext;
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    /**
     * 轮换密钥：生成新版本并设为活跃。
     *
     * <p>并发收敛：进入临界区前记录轮换纪元，若等待期间已有其他线程完成轮换，
     * 则直接采纳该结果返回，保证并发请求收敛为唯一的新版本。</p>
     */
    public int rotate() {
        long observedEpoch = rotationEpoch;
        synchronized (rotationLock) {
            if (rotationEpoch != observedEpoch) {
                int converged = active.getVersion();
                log.info("rotate converged: another rotation completed concurrently, activeVersion={}", converged);
                return converged;
            }
            Runnable hook = rotationHook;
            if (hook != null) {
                hook.run();
            }
            int newVersion = versions.keySet().stream().mapToInt(Integer::intValue).max().orElse(0) + 1;
            KeyVersion next = new KeyVersion(newVersion, AesGcmCipher.generateKey(), Instant.now());
            KeyVersion previous = active;
            versions.put(newVersion, next);
            active = next;
            if (previous != null && previous.getStatus() == KeyStatus.ACTIVE) {
                // 旧活跃版本降级为仅解密，保证任意时刻至多一个 ACTIVE 版本
                previous.transitionTo(KeyStatus.DECRYPT_ONLY);
                log.info("rotate: previous activeVersion={} demoted to DECRYPT_ONLY", previous.getVersion());
            }
            rotationEpoch++;
            log.info("rotate ok: newActiveVersion={}, totalVersions={}", newVersion, versions.size());
            return newVersion;
        }
    }

    /** 停用指定版本（ACTIVE -&gt; DISABLED）。 */
    public void deactivate(int version) {
        KeyVersion key = requireVersion(version);
        key.transitionTo(KeyStatus.DISABLED);
        log.info("deactivate ok: keyVersion={}, active={}", version,
                active != null && active.getStatus() == KeyStatus.ACTIVE);
    }

    /** 销毁指定版本（DISABLED -&gt; DESTROYED），密钥材料清零，不可逆。 */
    public void destroy(int version) {
        KeyVersion key = requireVersion(version);
        key.transitionTo(KeyStatus.DESTROYED);
        key.destroyMaterial();
        log.info("destroy ok: keyVersion={}, material cleared", version);
    }

    /** 当前活跃版本号；无活跃版本（活跃键被停用）时返回空。 */
    public Optional<Integer> activeVersion() {
        KeyVersion key = active;
        return key != null && key.getStatus() == KeyStatus.ACTIVE
                ? Optional.of(key.getVersion())
                : Optional.empty();
    }

    /** 所有版本的快照（不含密钥材料），用于观测与测试。 */
    public List<KeyVersion> listVersions() {
        List<KeyVersion> snapshot = new ArrayList<>(versions.values());
        snapshot.sort(Comparator.comparingInt(KeyVersion::getVersion));
        return snapshot;
    }

    /** 仅测试使用：设置轮换钩子。 */
    void setRotationHook(Runnable hook) {
        this.rotationHook = hook;
    }

    private KeyVersion requireVersion(int version) {
        KeyVersion key = versions.get(version);
        if (key == null) {
            log.warn("lifecycle op rejected: keyVersion={}, reason={}", version, FailureReason.KEY_NOT_FOUND);
            throw new KeyOperationException(FailureReason.KEY_NOT_FOUND, version,
                    "key version " + version + " does not exist");
        }
        return key;
    }

    /** AAD 绑定版本号：篡改密文中的版本字段会导致 GCM 认证失败。 */
    private static byte[] aad(int version) {
        return (Ciphertext.PREFIX + ":v" + version).getBytes(StandardCharsets.UTF_8);
    }
}
