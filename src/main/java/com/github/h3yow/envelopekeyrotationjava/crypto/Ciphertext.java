package com.github.h3yow.envelopekeyrotationjava.crypto;

import java.util.Base64;

/**
 * 信封加密密文的不可变表示，携带密钥版本信息以支持后续解析。
 *
 * <p>线性格式：{@code EK1.<version>.<base64url(payload)>}，
 * payload = wrappedDekLen(2B) | wrappedDek | iv(12B) | ciphertext+tag。</p>
 */
public record Ciphertext(int keyVersion, byte[] payload) {

    static final String PREFIX = "EK1";

    /** 编码为可传输字符串。 */
    public String encode() {
        return PREFIX + "." + keyVersion + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
    }

    /**
     * 解析字符串为 Ciphertext。
     *
     * <p>失败分类：</p>
     * <ul>
     *   <li>版本段缺失或无法解析为数字 -&gt; {@link FailureReason#VERSION_MISSING}</li>
     *   <li>整体结构或 payload 编码非法 -&gt; {@link FailureReason#CIPHERTEXT_MALFORMED}</li>
     * </ul>
     */
    public static Ciphertext parse(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED, "ciphertext is empty");
        }
        String[] parts = encoded.split("\\.", -1);
        if (parts.length != 3 || !PREFIX.equals(parts[0])) {
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED,
                    "ciphertext must have format " + PREFIX + ".<version>.<payload>");
        }
        final int version;
        try {
            version = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new KeyOperationException(FailureReason.VERSION_MISSING,
                    "ciphertext does not carry a valid key version");
        }
        if (version <= 0) {
            throw new KeyOperationException(FailureReason.VERSION_MISSING,
                    "ciphertext carries a non-positive key version");
        }
        if (parts[2].isEmpty()) {
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED, "ciphertext payload is empty");
        }
        final byte[] payload;
        try {
            payload = Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED, "ciphertext payload is not valid base64url");
        }
        return new Ciphertext(version, payload);
    }
}
