package com.github.h3yow.envelopekeyrotationjava.crypto;

import java.time.Instant;
import java.util.Arrays;

/**
 * 一个密钥版本：进程内保存密钥材料与生命周期状态。
 *
 * <p>密钥材料只允许在本类内部使用，不对外暴露；toString 不得输出材料。</p>
 */
public final class KeyVersion {

    private final int version;
    private final Instant createdAt;
    private volatile KeyStatus status;
    private byte[] keyMaterial;

    KeyVersion(int version, byte[] keyMaterial, Instant createdAt) {
        this.version = version;
        this.keyMaterial = keyMaterial;
        this.createdAt = createdAt;
        this.status = KeyStatus.ACTIVE;
    }

    public int getVersion() {
        return version;
    }

    public KeyStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * 状态迁移：ACTIVE -&gt; DECRYPT_ONLY（轮换时内部触发）或 ACTIVE -&gt; DISABLED；
     * DECRYPT_ONLY -&gt; DISABLED；DISABLED -&gt; DESTROYED。均不可逆。
     * 非法迁移抛出 {@link FailureReason#ILLEGAL_STATE_TRANSITION}。
     */
    synchronized void transitionTo(KeyStatus target) {
        boolean legal = switch (status) {
            case ACTIVE -> target == KeyStatus.DECRYPT_ONLY || target == KeyStatus.DISABLED;
            case DECRYPT_ONLY -> target == KeyStatus.DISABLED;
            case DISABLED -> target == KeyStatus.DESTROYED;
            case DESTROYED -> false;
        };
        if (!legal) {
            throw new KeyOperationException(FailureReason.ILLEGAL_STATE_TRANSITION, version,
                    "illegal key state transition: " + status + " -> " + target + " (version=" + version + ")");
        }
        this.status = target;
    }

    /** 返回密钥材料的内部引用，仅限包内加密使用；销毁后返回 null。 */
    byte[] keyMaterial() {
        return keyMaterial;
    }

    /** 销毁密钥材料（清零并置空），不可逆。 */
    synchronized void destroyMaterial() {
        if (keyMaterial != null) {
            Arrays.fill(keyMaterial, (byte) 0);
            keyMaterial = null;
        }
    }

    /** 仅供测试与诊断：密钥材料是否已被销毁清零。 */
    public boolean isMaterialDestroyed() {
        return keyMaterial == null;
    }

    @Override
    public String toString() {
        return "KeyVersion{version=" + version + ", status=" + status + ", createdAt=" + createdAt + "}";
    }
}
