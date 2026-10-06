package com.github.h3yow.envelopekeyrotationjava.web;

import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.migration.BatchMigrationService;
import com.github.h3yow.envelopekeyrotationjava.migration.MigrationResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 批量迁移接口：把存量密文统一重加密为当前加密版本，支持幂等重跑与中断续跑。
 */
@RestController
@RequestMapping("/api/migrations")
public class MigrationController {

    /** 默认单片大小：不显式指定时一次处理 100 条，便于观察续跑语义。 */
    static final int DEFAULT_MAX_BATCH = 100;

    public record MigrationRequest(List<String> ids, Integer maxBatch, String cursor) {}

    private final BatchMigrationService migrationService;

    public MigrationController(BatchMigrationService migrationService) {
        this.migrationService = migrationService;
    }

    /**
     * 发起/续跑一次批量迁移。
     * 不传 ids 表示迁移全部记录；maxBatch 限定本次处理条数（分片/续跑）；
     * cursor 传入上次响应中的 nextCursor 以续跑。
     * hasMore=true 时携带 nextCursor 再次调用即可从中断处继续。
     */
    @PostMapping
    public MigrationResult migrate(@RequestBody(required = false) MigrationRequest request) {
        if (request == null) {
            return migrationService.migrateBatch(null, DEFAULT_MAX_BATCH, null);
        }
        int maxBatch = request.maxBatch() == null ? DEFAULT_MAX_BATCH : request.maxBatch();
        if (maxBatch <= 0) {
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED, "maxBatch must be positive");
        }
        return migrationService.migrateBatch(request.ids(), maxBatch, request.cursor());
    }
}
