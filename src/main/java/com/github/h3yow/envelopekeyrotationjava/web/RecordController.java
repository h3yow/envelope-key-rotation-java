package com.github.h3yow.envelopekeyrotationjava.web;

import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import com.github.h3yow.envelopekeyrotationjava.storage.CiphertextStore;
import com.github.h3yow.envelopekeyrotationjava.storage.StoredRecord;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 存量密文记录的读写接口：模拟业务库的写入与读取，供批量迁移操作。
 *
 * <p>读取时严格按密文携带的版本解密，因此无论记录是否已迁移，
 * 返回的明文都正确，且 keyVersion 反映该记录当前实际所处的版本。</p>
 */
@RestController
@RequestMapping("/api/records")
public class RecordController {

    public record SaveRequest(String id, String plaintext) {}
    public record RecordView(String id, String ciphertext, int keyVersion) {}
    public record ReadResponse(String id, String plaintext, int keyVersion) {}

    private final KeyManager keyManager;
    private final CiphertextStore store;

    public RecordController(KeyManager keyManager, CiphertextStore store) {
        this.keyManager = keyManager;
        this.store = store;
    }

    /** 用当前活跃版本加密并保存（或覆盖）一条记录。 */
    @PostMapping
    public RecordView save(@RequestBody SaveRequest request) {
        if (request == null || request.id() == null || request.id().isBlank()) {
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED, "record id must not be blank");
        }
        if (request.plaintext() == null) {
            throw new KeyOperationException(FailureReason.CIPHERTEXT_MALFORMED, "plaintext must not be null");
        }
        String ciphertext = keyManager.encrypt(request.plaintext().getBytes(StandardCharsets.UTF_8));
        StoredRecord saved = store.save(request.id(), ciphertext);
        return new RecordView(saved.id(), saved.ciphertext(), saved.keyVersion());
    }

    /** 读取记录并解密，返回明文与其实际密钥版本。 */
    @GetMapping("/{id}")
    public ReadResponse read(@PathVariable String id) {
        StoredRecord record = store.get(id)
                .orElseThrow(() -> new KeyOperationException(FailureReason.KEY_NOT_FOUND,
                        "record " + id + " does not exist"));
        byte[] plaintext = keyManager.decrypt(record.ciphertext());
        return new ReadResponse(record.id(),
                new String(plaintext, StandardCharsets.UTF_8), record.keyVersion());
    }

    /** 列出全部记录（密文本身可对外展示，不含任何密钥材料）。 */
    @GetMapping
    public List<RecordView> list() {
        return store.all().stream()
                .map(r -> new RecordView(r.id(), r.ciphertext(), r.keyVersion()))
                .toList();
    }
}
