package com.github.h3yow.envelopekeyrotationjava.migration;

import java.util.List;

/**
 * 一次批量迁移（或一次续跑分片）的结果。
 *
 * @param targetVersion  本次迁移固定写入的目标版本（任务开始时确定）
 * @param processed      本次实际重加密的记录数
 * @param skipped        本次跳过的记录数（已经是目标版本，幂等）
 * @param failed         本次失败的记录数（单条失败不中断整批）
 * @param totalCandidates 本次扫描到的候选记录总数
 * @param hasMore        是否还有未处理记录（用于中断续跑）
 * @param nextCursor     续跑游标；无更多记录时为 null
 * @param failures       失败明细（id + 原因），不含明文/密文内容
 */
public record MigrationResult(int targetVersion, int processed, int skipped, int failed,
                              int totalCandidates, boolean hasMore, String nextCursor,
                              List<ItemFailure> failures) {

    /** 单条记录迁移失败的诊断信息。 */
    public record ItemFailure(String id, String reason, String message) {
    }
}
