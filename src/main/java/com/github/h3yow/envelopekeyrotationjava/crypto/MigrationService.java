package com.github.h3yow.envelopekeyrotationjava.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 批量迁移服务：把存储中的旧版本密文统一重加密到当前活跃版本。
 *
 * <p>语义约定：</p>
 * <ul>
 *   <li><b>幂等</b>：已在当前活跃版本的记录原样跳过，重复执行同一批迁移
 *       不产生重复结果，也不会破坏已迁移数据。</li>
 *   <li><b>可续跑</b>：逐条处理、逐条生效（CAS 写回即完成该条），中途中断后
 *       重新执行同一批请求即可从断点继续，已处理部分不会被重新处理、不会回退。</li>
 *   <li><b>并发收敛</b>：写回采用 compare-and-set，仅当存储值仍等于迁移前读到的值才生效；
 *       多个迁移者或并发业务写冲突时重新读取评估，最终收敛为同一结果，
 *       不会出现两套并行的迁移方向。</li>
 *   <li><b>不停服</b>：迁移只新增当前版本密文，旧版本在迁移期间保持可解密，
 *       读写任意时刻结论一致。</li>
 *   <li><b>容量边界</b>：保留版本数达到上限时，迁移请求与轮换一样被明确拒绝
 *       （{@link FailureReason#VERSION_LIMIT_EXCEEDED}），绝不悄悄淘汰最老版本。</li>
 * </ul>
 */
@Service
public class MigrationService {

    private static final Logger log = LoggerFactory.getLogger(MigrationService.class);

    /** 单条记录在并发冲突下的最大重试次数。 */
    private static final int MAX_ATTEMPTS_PER_RECORD = 5;

    private final KeyManager keyManager;
    private final CiphertextStore store;

    public MigrationService(KeyManager keyManager, CiphertextStore store) {
        this.keyManager = keyManager;
        this.store = store;
    }

    /** 迁移存储中的全部记录。 */
    public MigrationReport migrateAll() {
        return migrateBatch(store.snapshot().keySet());
    }

    /**
     * 迁移指定的一批记录到当前活跃版本。
     *
     * <p>可反复执行：已迁移的记录会被识别为 alreadyCurrent 并跳过；
     * 中断后重跑同一批请求即可续跑。单条失败不阻断其余记录，明细计入报告。</p>
     *
     * @throws KeyOperationException 版本数达上限（VERSION_LIMIT_EXCEEDED）或无活跃版本（NO_ACTIVE_KEY）
     */
    public MigrationReport migrateBatch(Collection<String> ids) {
        assertCapacity();
        int targetVersion = keyManager.activeVersion()
                .orElseThrow(() -> new KeyOperationException(FailureReason.NO_ACTIVE_KEY,
                        "no active key version available for migration"));
        int migrated = 0;
        int alreadyCurrent = 0;
        List<MigrationReport.Failure> failures = new ArrayList<>();
        for (String id : ids) {
            Outcome outcome = migrateOne(id, targetVersion);
            switch (outcome.kind()) {
                case MIGRATED -> migrated++;
                case ALREADY_CURRENT -> alreadyCurrent++;
                case FAILED -> failures.add(new MigrationReport.Failure(id, outcome.reason()));
            }
        }
        MigrationReport report = new MigrationReport(
                ids.size(), migrated, alreadyCurrent, failures.size(), List.copyOf(failures));
        log.info("migration batch done: targetVersion={}, total={}, migrated={}, alreadyCurrent={}, failed={}",
                targetVersion, report.total(), report.migrated(), report.alreadyCurrent(), report.failed());
        return report;
    }

    /** 迁移单条记录；并发冲突时重读重试，收敛或超出重试上限为止。 */
    private Outcome migrateOne(String id, int targetVersion) {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS_PER_RECORD; attempt++) {
            String current = store.read(id).orElse(null);
            if (current == null) {
                log.warn("migration skipped: id={}, reason=record not found", id);
                return Outcome.failed(FailureReason.KEY_NOT_FOUND);
            }
            final int sourceVersion;
            try {
                sourceVersion = Ciphertext.parse(current).keyVersion();
            } catch (KeyOperationException e) {
                log.warn("migration failed: id={}, reason={}", id, e.getReason());
                return Outcome.failed(e.getReason());
            }
            if (sourceVersion == targetVersion) {
                // 幂等：已是当前版本（包括被并发迁移者抢先完成的情况），原样跳过
                return Outcome.alreadyCurrent();
            }
            final String reencrypted;
            try {
                reencrypted = keyManager.reencrypt(current);
            } catch (KeyOperationException e) {
                log.warn("migration failed: id={}, fromVersion={}, reason={}", id, sourceVersion, e.getReason());
                return Outcome.failed(e.getReason());
            }
            if (store.compareAndSet(id, current, reencrypted)) {
                log.info("migration ok: id={}, fromVersion={}, toVersion={}, attempt={}",
                        id, sourceVersion, targetVersion, attempt);
                return Outcome.migrated();
            }
            // CAS 失败：被并发修改，重新读取评估（可能已被并发迁移者完成）
            log.info("migration conflict: id={}, attempt={}, re-reading", id, attempt);
        }
        log.warn("migration failed: id={}, reason=concurrent modification not converged", id);
        return Outcome.failed(FailureReason.ILLEGAL_STATE_TRANSITION);
    }

    /** 容量边界：版本数达上限时明确拒绝迁移请求。 */
    private void assertCapacity() {
        if (keyManager.versionCount() >= keyManager.maxVersions()) {
            log.warn("migration rejected: versionCount={}, maxVersions={}, reason={}",
                    keyManager.versionCount(), keyManager.maxVersions(), FailureReason.VERSION_LIMIT_EXCEEDED);
            throw new KeyOperationException(FailureReason.VERSION_LIMIT_EXCEEDED,
                    "retained key version limit reached (" + keyManager.maxVersions() + "), migration rejected");
        }
    }

    private enum OutcomeKind { MIGRATED, ALREADY_CURRENT, FAILED }

    private record Outcome(OutcomeKind kind, FailureReason reason) {
        static Outcome migrated() {
            return new Outcome(OutcomeKind.MIGRATED, null);
        }

        static Outcome alreadyCurrent() {
            return new Outcome(OutcomeKind.ALREADY_CURRENT, null);
        }

        static Outcome failed(FailureReason reason) {
            return new Outcome(OutcomeKind.FAILED, reason);
        }
    }
}
