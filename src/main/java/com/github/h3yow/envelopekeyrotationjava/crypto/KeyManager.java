package com.github.h3yow.envelopekeyrotationjava.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.function.IntPredicate;

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
 *
 * <p>版本保留上限：保留版本（未销毁）数量达到 {@code maxVersions} 时，轮换请求以
 * {@link FailureReason#VERSION_LIMIT_EXCEEDED} 被明确拒绝——不会悄悄丢弃最老版本。
 * 销毁边界：版本仍被存量密文引用时，销毁请求以 {@link FailureReason#KEY_STILL_REFERENCED}
 * 被拒绝，该原因与其他失败明确可区分。</p>
 */
@Service
public class KeyManager {

    private static final Logger log = LoggerFactory.getLogger(KeyManager.class);

    /** 默认保留版本上限。 */
    static final int DEFAULT_MAX_VERSIONS = 10;

    private static final int WRAP_IV_OFF = 0;
    private static final int WRAPPED_DEK_OFF = WRAP_IV_OFF + AesGcmCipher.IV_BYTES;
    private static final int WRAPPED_DEK_LEN = AesGcmCipher.KEY_BYTES + AesGcmCipher.TAG_BITS / 8;
    private static final int DATA_IV_OFF = WRAPPED_DEK_OFF + WRAPPED_DEK_LEN;
    private static final int DATA_CT_OFF = DATA_IV_OFF + AesGcmCipher.IV_BYTES;
    private static final int MIN_PAYLOAD_LEN = DATA_CT_OFF + AesGcmCipher.TAG_BITS / 8;

    private final ConcurrentHashMap<Integer, KeyVersion> versions = new ConcurrentHashMap<>();
    private final Object rotationLock = new Object();
    private volatile int maxVersions;

    private volatile KeyVersion active;
    private volatile long rotationEpoch;

    /**
     * 引用检查器：入参为版本号，返回该版本是否仍被存量密文引用。
     * 默认不引用任何版本；由迁移/存储层在装配时注册。
     */
    private volatile IntPredicate referenceChecker = version -> false;

    /** 测试钩子：在轮换临界区内、新版本创建前执行。仅用于并发测试，生产环境不得设置。 */
    private volatile Runnable rotationHook;

    /** 便捷构造器：使用 {@link #DEFAULT_MAX_VERSIONS} 作为保留上限。 */
    public KeyManager() {
        this(DEFAULT_MAX_VERSIONS);
    }

    /**
     * 主构造器：Spring 注入 {@code crypto.max-versions}（缺省 10）；
     * 单元测试也可直接传入显式上限。
     */
    @org.springframework.beans.factory.annotation.Autowired
    public KeyManager(@Value("${crypto.max-versions:" + DEFAULT_MAX_VERSIONS + "}") int maxVersions) {
        if (maxVersions < 1) {
            throw new IllegalArgumentException("maxVersions must be at least 1");
        }
        this.maxVersions = maxVersions;
        KeyVersion initial = new KeyVersion(1, AesGcmCipher.generateKey(), Instant.now());
        versions.put(1, initial);
        active = initial;
        log.info("key manager initialized, activeVersion={}, maxVersions={}", 1, maxVersions);
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
            int retained = retainedVersionCount();
            if (retained >= maxVersions) {
                log.warn("rotate rejected: retainedVersions={}, maxVersions={}, reason={}",
                        retained, maxVersions, FailureReason.VERSION_LIMIT_EXCEEDED);
                throw new KeyOperationException(FailureReason.VERSION_LIMIT_EXCEEDED,
                        "retained version count " + retained + " reached limit " + maxVersions
                                + "; migrate data off old versions and destroy them before rotating");
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

    /**
     * 销毁指定版本（DISABLED -&gt; DESTROYED），密钥材料清零，不可逆。
     *
     * <p>边界：只要仍有任何存量密文引用该版本（无论其当前处于何种状态），
     * 一律以 {@link FailureReason#KEY_STILL_REFERENCED} 拒绝，且该检查先于状态迁移执行，
     * 不会留下半销毁状态。</p>
     */
    public void destroy(int version) {
        KeyVersion key = requireVersion(version);
        if (referenceChecker.test(version)) {
            log.warn("destroy rejected: keyVersion={} still referenced, reason={}",
                    version, FailureReason.KEY_STILL_REFERENCED);
            throw new KeyOperationException(FailureReason.KEY_STILL_REFERENCED, version,
                    "key version " + version + " is still referenced by stored ciphertext and cannot be destroyed");
        }
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

    /** 当前保留版本（未销毁）数量。销毁后的版本不再计入保留上限。 */
    public int retainedVersionCount() {
        return (int) versions.values().stream()
                .filter(kv -> kv.getStatus() != KeyStatus.DESTROYED)
                .count();
    }

    /** 保留版本上限。 */
    public int maxVersions() {
        return maxVersions;
    }

    /**
     * 下调保留版本上限（运维收紧容量）。
     *
     * <p>允许把上限调到小于当前保留数：已存在的版本不会被静默删除，但系统进入"超限"状态——
     * 之后的轮换被拒绝（守卫条件 retained &ge; maxVersions 在超限时同样成立），
     * 迁移在 retained &gt; maxVersions 时也被明确拒绝，必须先下线（停用+销毁）
     * 无引用的旧版本，使保留数回落到新上限以内。</p>
     */
    public void reconfigureMaxVersions(int newLimit) {
        if (newLimit < 1) {
            throw new IllegalArgumentException("maxVersions must be at least 1");
        }
        synchronized (rotationLock) {
            int old = this.maxVersions;
            this.maxVersions = newLimit;
            log.info("maxVersions reconfigured: {} -> {}, retainedVersions={}",
                    old, newLimit, retainedVersionCount());
        }
    }

    /**
     * 迁移前置校验：迁移本身不新增版本，但当保留版本数已<b>超过</b>上限
     * （例如上限被下调）时明确拒绝，避免在超限状态下继续堆积；
     * 恰好等于上限时迁移仍允许执行——迁移是把数据搬离旧版本、使其可销毁的唯一出路。
     */
    public void checkMigrationCapacity() {
        int retained = retainedVersionCount();
        if (retained > maxVersions) {
            log.warn("migration rejected: retainedVersions={}, maxVersions={}, reason={}",
                    retained, maxVersions, FailureReason.VERSION_LIMIT_EXCEEDED);
            throw new KeyOperationException(FailureReason.VERSION_LIMIT_EXCEEDED,
                    "retained version count " + retained + " exceeds limit " + maxVersions
                            + "; destroy unreferenced old versions first");
        }
    }

    /** 注册"版本是否仍被密文引用"的检查器（由存储/迁移层在装配时调用）。 */
    public void setReferenceChecker(IntPredicate checker) {
        this.referenceChecker = checker == null ? version -> false : checker;
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
