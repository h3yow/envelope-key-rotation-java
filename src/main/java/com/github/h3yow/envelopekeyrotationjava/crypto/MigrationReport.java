package com.github.h3yow.envelopekeyrotationjava.crypto;

import java.util.List;

/**
 * 一次批量迁移的结果报告。
 *
 * @param total          本次请求处理的记录数
 * @param migrated       本次实际重加密的记录数
 * @param alreadyCurrent 已在当前活跃版本、被原样跳过的记录数（幂等语义的体现）
 * @param failed         处理失败的记录数（明细见 failures）
 * @param failures       失败明细：记录 id 与可区分的失败原因，不含明文/密文/密钥材料
 */
public record MigrationReport(int total, int migrated, int alreadyCurrent, int failed,
                              List<Failure> failures) {

    /** 单条记录的失败明细。 */
    public record Failure(String id, FailureReason reason) {}

    /** 是否全部处理成功（允许 alreadyCurrent，不允许 failed）。 */
    public boolean isComplete() {
        return failed == 0;
    }
}
