package com.github.h3yow.envelopekeyrotationjava.crypto;

/**
 * In-process representation of one key version. Package-private: key material
 * never leaves the crypto package.
 */
final class KeyVersion {

    private final int version;
    private volatile KeyStatus status;
    private byte[] material;

    KeyVersion(int version, byte[] material) {
        this.version = version;
        this.material = material;
        this.status = KeyStatus.ACTIVE;
    }

    int getVersion() {
        return version;
    }

    KeyStatus getStatus() {
        return status;
    }

    void setStatus(KeyStatus status) {
        this.status = status;
    }

    byte[] getMaterial() {
        return material;
    }

    void eraseMaterial() {
        this.material = null;
    }
}
