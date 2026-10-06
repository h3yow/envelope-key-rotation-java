package com.github.h3yow.envelopekeyrotationjava.tests.migration;

import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyStatus;
import com.github.h3yow.envelopekeyrotationjava.migration.BatchMigrationService;
import com.github.h3yow.envelopekeyrotationjava.migration.MigrationResult;
import com.github.h3yow.envelopekeyrotationjava.storage.CiphertextStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 迁移与版本保留容量的边界测试。
 *
 * <p>容量规则：</p>
 * <ul>
 *   <li>保留版本数 <b>达到</b>上限：拒绝轮换；迁移仍允许——迁移不新增版本，
 *       且它是把数据搬离旧版本、使其可销毁、从而释放名额的唯一出路；</li>
 *   <li>保留版本数 <b>超过</b>上限（上限被下调）：迁移也被明确拒绝，
 *       必须先销毁无引用旧版本使保留数回落，绝不允许静默丢版本。</li>
 * </ul>
 */
class MigrationCapacityTest {

    private static final Logger log = LoggerFactory.getLogger(MigrationCapacityTest.class);

    private record Sys(KeyManager km, CiphertextStore store, BatchMigrationService migration) {
        static Sys of(int limit) {
            KeyManager km = new KeyManager(limit);
            CiphertextStore store = new CiphertextStore();
            BatchMigrationService migration = new BatchMigrationService(km, store);
            km.setReferenceChecker(store::isReferenced);
            return new Sys(km, store, migration);
        }
    }

    @Test
    void migrationAllowedAtLimitButRotationRejected() {
        Sys s = Sys.of(2);
        s.store().save("r1", s.km().encrypt("payload".getBytes(StandardCharsets.UTF_8)));
        int v2 = s.km().rotate(); // 保留数达到上限 2
        assertEquals(2, s.km().retainedVersionCount());

        KeyOperationException blocked = assertThrows(KeyOperationException.class, s.km()::rotate);
        assertEquals(FailureReason.VERSION_LIMIT_EXCEEDED, blocked.getReason());

        MigrationResult result = s.migration().migrateAll(null);
        log.info("场景: 保留数=上限 -> 轮换拒绝，迁移放行: processed={}, target={}",
                result.processed(), result.targetVersion());
        assertEquals(1, result.processed());
        assertEquals(v2, result.targetVersion());
        assertEquals(0, s.store().referenceCount(1));
    }

    @Test
    void migrationRejectedAfterLimitLoweredBelowRetainedCount() {
        Sys s = Sys.of(5);
        s.store().save("r1", s.km().encrypt("payload".getBytes(StandardCharsets.UTF_8)));
        s.km().rotate(); // v2
        s.km().rotate(); // v3，保留数 3

        // 运维把上限从 5 下调到 2：保留数 3 > 2，进入超限状态，已有版本不被删除
        s.km().reconfigureMaxVersions(2);
        assertEquals(3, s.km().retainedVersionCount());
        assertEquals(3, s.km().listVersions().size(), "下调上限绝不能静默删除任何版本");
        log.info("场景: 上限下调至 2 而保留数为 3 -> 版本一个不少: versions={}",
                s.km().listVersions().stream().map(k -> k.getVersion()).toList());

        KeyOperationException migrationEx = assertThrows(KeyOperationException.class,
                () -> s.migration().migrateAll(null));
        assertEquals(FailureReason.VERSION_LIMIT_EXCEEDED, migrationEx.getReason());
        KeyOperationException rotationEx = assertThrows(KeyOperationException.class, s.km()::rotate);
        assertEquals(FailureReason.VERSION_LIMIT_EXCEEDED, rotationEx.getReason());
        log.info("场景: 超限时迁移与轮换都被明确拒绝 -> 迁移 reason={}, 轮换 reason={}",
                migrationEx.getReason(), rotationEx.getReason());

        // 出路：先销毁一个无引用的旧版本（v1 还被 r1 引用——先把 r1 搬到 v3 不可能，
        // 因为迁移被拒；这里 v2 无任何引用，可直接停用+销毁，使保留数回落到上限以内）
        assertEquals(0, s.store().referenceCount(2));
        s.km().deactivate(2);
        s.km().destroy(2);
        assertEquals(2, s.km().retainedVersionCount());
        log.info("场景: 销毁无引用的 v2 后保留数回落 -> retained={}", s.km().retainedVersionCount());

        // 回落到上限以内：迁移恢复，可以把 r1 搬到当前活跃版本，之后 v1 也可下线
        MigrationResult result = s.migration().migrateAll(null);
        assertEquals(1, result.processed());
        s.km().deactivate(1);
        s.km().destroy(1);
        assertEquals(KeyStatus.DESTROYED, s.km().listVersions().get(0).getStatus());
        assertArrayEquals("payload".getBytes(StandardCharsets.UTF_8),
                s.km().decrypt(s.store().get("r1").orElseThrow().ciphertext()));
        log.info("场景: 容量回落之后迁移恢复，旧版本依次下线，数据可读");
    }

    @Test
    void belowLimitEverythingProceeds() {
        Sys s = Sys.of(10);
        s.store().save("a", s.km().encrypt("a".getBytes(StandardCharsets.UTF_8)));
        s.km().rotate();
        MigrationResult result = s.migration().migrateAll(null);
        assertEquals(1, result.processed());
        int v3 = s.km().rotate();
        assertEquals(3, v3);
        log.info("场景: 未达上限 -> 迁移、轮换都正常, activeVersion={}", v3);
    }
}
