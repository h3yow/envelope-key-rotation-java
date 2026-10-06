package com.github.h3yow.envelopekeyrotationjava.migration;

import com.github.h3yow.envelopekeyrotationjava.crypto.Ciphertext;
import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.storage.CiphertextStore;
import com.github.h3yow.envelopekeyrotationjava.storage.StoredRecord;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 批量重加密迁移服务：把存量旧版本密文逐步搬到当前加密版本。
 *
 * <p>核心语义：</p>
 * <ul>
 *   <li><b>正确性</b>：先解密旧密文、再用当前活跃版本重新加密；记录级原子替换，
 *       迁移前后明文逐字节一致，读永远看到完整的旧密文或完整新密文。</li>
 *   <li><b>幂等</b>：已经处于目标版本的记录直接跳过；对记录的替换采用
 *       "比较当前密文再替换"（CAS），并发或重复执行都不会重复处理、不会回退。</li>
 *   <li><b>可续跑</b>：游标编码"目标版本 + 候选列表起点"，中断后凭游标续跑；
 *       已处理记录即使在更靠前位置被重扫到，也因已是目标版本而跳过，绝不重做。</li>
 *   <li><b>收敛</b>：迁移单飞（single-flight），同一时刻只有一个迁移任务真正执行，
 *       并发发起的迁移共用同一个目标版本，不会出现两套并行迁移方向。</li>
 * </ul>
 */
@Service
public class BatchMigrationService {

    private static final Logger log = LoggerFactory.getLogger(BatchMigrationService.class);

    private final KeyManager keyManager;
    private final CiphertextStore store;
    private final ReentrantLock migrationLock = new ReentrantLock();

    /** 测试钩子：在"解密旧密文之后、用活跃版本重加密之前"执行，用于构造迁移中途轮换。 */
    private volatile Runnable beforeReEncryptHook;

    public BatchMigrationService(KeyManager keyManager, CiphertextStore store) {
        this.keyManager = keyManager;
        this.store = store;
    }

    /** 仅供测试：设置重加密前钩子，生产环境不得设置。 */
    public void setBeforeReEncryptHook(Runnable hook) {
        this.beforeReEncryptHook = hook;
    }

    /** 装配时把存储的引用计数接到密钥管理器上，作为销毁边界的判定依据。 */
    @PostConstruct
    void registerReferenceChecker() {
        keyManager.setReferenceChecker(store::isReferenced);
    }

    /**
     * 迁移指定 id 集合（null/空 表示全部记录），每片最多 maxBatch 条；
     * cursor 为上次返回的续跑游标（null 表示从头开始）。
     */
    public MigrationResult migrateBatch(List<String> ids, int maxBatch, String cursor) {
        if (maxBatch <= 0) {
            throw new IllegalArgumentException("maxBatch must be positive");
        }
        // 单飞：并发发起的迁移排队执行，后到者以"续跑"方式收敛，绝不并行两个迁移方向
        migrationLock.lock();
        try {
            keyManager.checkMigrationCapacity();

            List<String> candidates = (ids == null || ids.isEmpty()) ? store.ids() : sortedDistinct(ids);
            int targetVersion = keyManager.activeVersion()
                    .orElseThrow(() -> new KeyOperationException(FailureReason.NO_ACTIVE_KEY,
                            "no active key version available as migration target"));

            CursorPosition start = CursorPosition.parse(cursor, targetVersion);
            int fromIndex = Math.min(start.index(), candidates.size());

            int processed = 0;
            int skipped = 0;
            int failed = 0;
            List<MigrationResult.ItemFailure> failures = new ArrayList<>();

            int endIndex = Math.min(fromIndex + maxBatch, candidates.size());
            for (int i = fromIndex; i < endIndex; i++) {
                String id = candidates.get(i);
                Outcome outcome = migrateOne(id, targetVersion);
                switch (outcome.kind) {
                    case PROCESSED -> processed++;
                    case SKIPPED -> skipped++;
                    case FAILED -> {
                        failed++;
                        failures.add(new MigrationResult.ItemFailure(id, outcome.reason(), outcome.message()));
                    }
                }
            }

            boolean hasMore = endIndex < candidates.size();
            String nextCursor = hasMore ? CursorPosition.encode(targetVersion, endIndex) : null;
            MigrationResult result = new MigrationResult(targetVersion, processed, skipped, failed,
                    candidates.size(), hasMore, nextCursor, List.copyOf(failures));
            log.info("migration batch done: targetVersion={}, window=[{},{}), processed={}, skipped={}, "
                            + "failed={}, candidates={}, hasMore={}",
                    targetVersion, fromIndex, endIndex, processed, skipped, failed,
                    candidates.size(), hasMore);
            return result;
        } finally {
            migrationLock.unlock();
        }
    }

    /** 无游标、单片处理全部候选记录的便捷入口。 */
    public MigrationResult migrateAll(List<String> ids) {
        return migrateBatch(ids, Integer.MAX_VALUE, null);
    }

    /**
     * 迁移单条记录到目标版本。
     *
     * <p>处理顺序保证幂等与不回退：</p>
     * <ol>
     *   <li>记录不存在（可能已被删除）→ 跳过；</li>
     *   <li>记录已是目标版本 → 跳过（重复执行的关键）；</li>
     *   <li>解密失败（旧版本已停用/销毁、密文损坏等）→ 记为失败，不中断整批；</li>
     *   <li>以当前活跃版本重加密并 CAS 替换；替换失败说明已被其他迁移者处理 → 跳过。</li>
     * </ol>
     */
    private Outcome migrateOne(String id, int targetVersion) {
        Optional<StoredRecord> found = store.get(id);
        if (found.isEmpty()) {
            return Outcome.skipped();
        }
        StoredRecord record = found.get();
        if (record.keyVersion() == targetVersion) {
            log.info("migrate skip: id={} already at targetVersion={}", id, targetVersion);
            return Outcome.skipped();
        }
        final byte[] plaintext;
        try {
            plaintext = keyManager.decrypt(record.ciphertext());
        } catch (KeyOperationException e) {
            log.warn("migrate item failed at decrypt stage: id={}, keyVersion={}, reason={}",
                    id, record.keyVersion(), e.getReason());
            return Outcome.failed(e.getReason().name(),
                    "source version " + record.keyVersion() + " cannot be decrypted: " + e.getReason());
        }
        Runnable hook = beforeReEncryptHook;
        if (hook != null) {
            hook.run();
        }
        String newCiphertext = keyManager.encrypt(plaintext);
        // 防御性自检：批次开始后若活跃版本被轮换，重加密产物会声明新版本——
        // 绝不把它按旧目标版本写入（避免一条记录被朝两个方向迁移），本条记为可重试失败。
        if (Ciphertext.parse(newCiphertext).keyVersion() != targetVersion) {
            return Outcome.failed(FailureReason.ILLEGAL_STATE_TRANSITION.name(),
                    "active version changed within migration; retry to converge");
        }
        boolean replaced = store.replaceIfUnchanged(
                id, record.ciphertext(), newCiphertext, targetVersion);
        if (replaced) {
            log.info("migrate processed: id={}, keyVersion {} -> {}",
                    id, record.keyVersion(), targetVersion);
            return Outcome.processed();
        }
        // CAS 失败：记录已被并发迁移/覆盖处理过，本次收敛为跳过，绝不覆盖他人结果
        log.info("migrate skip after CAS miss: id={}, handled concurrently", id);
        return Outcome.skipped();
    }

    private static List<String> sortedDistinct(List<String> ids) {
        return ids.stream().filter(id -> id != null && !id.isBlank()).distinct().sorted().toList();
    }

    /** 单条记录的处理结论，附带失败诊断。 */
    private static final class Outcome {
        enum Kind { PROCESSED, SKIPPED, FAILED }

        private final Kind kind;
        private final String reason;
        private final String message;

        private Outcome(Kind kind, String reason, String message) {
            this.kind = kind;
            this.reason = reason;
            this.message = message;
        }

        static Outcome processed() {
            return new Outcome(Kind.PROCESSED, null, null);
        }

        static Outcome skipped() {
            return new Outcome(Kind.SKIPPED, null, null);
        }

        static Outcome failed(String reason, String message) {
            return new Outcome(Kind.FAILED, reason, message);
        }

        String reason() {
            return reason;
        }

        String message() {
            return message;
        }
    }

    /**
     * 续跑游标：base64url("v&lt;targetVersion&gt;:&lt;nextIndex&gt;")。
     * 绑定目标版本是为了防止"上一轮迁到 v3 的游标被拿去续跑到 v4"时错判幂等：
     * 目标不一致一律拒绝，要求从头开启新方向的迁移。
     */
    record CursorPosition(int targetVersion, int index) {

        static String encode(int targetVersion, int index) {
            String raw = "v" + targetVersion + ":" + index;
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(raw.getBytes(StandardCharsets.UTF_8));
        }

        static CursorPosition parse(String cursor, int expectedTargetVersion) {
            if (cursor == null || cursor.isBlank()) {
                return new CursorPosition(expectedTargetVersion, 0);
            }
            final String raw;
            try {
                raw = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED,
                        "migration cursor is not valid base64url");
            }
            String[] parts = raw.split(":", 2);
            if (parts.length != 2 || !parts[0].startsWith("v")) {
                throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED,
                        "migration cursor is malformed");
            }
            final int cursorVersion;
            final int index;
            try {
                cursorVersion = Integer.parseInt(parts[0].substring(1));
                index = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED,
                        "migration cursor carries non-numeric fields");
            }
            if (index < 0) {
                throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED,
                        "migration cursor carries negative offset");
            }
            if (cursorVersion != expectedTargetVersion) {
                throw new KeyOperationException(FailureReason.ILLEGAL_STATE_TRANSITION,
                        "cursor targets version " + cursorVersion + " but current active version is "
                                + expectedTargetVersion + "; start a fresh migration for the new target");
            }
            return new CursorPosition(cursorVersion, index);
        }
    }
}
