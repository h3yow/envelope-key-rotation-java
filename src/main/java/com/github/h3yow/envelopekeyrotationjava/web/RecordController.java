package com.github.h3yow.envelopekeyrotationjava.web;

import com.github.h3yow.envelopekeyrotationjava.crypto.Ciphertext;
import com.github.h3yow.envelopekeyrotationjava.crypto.CiphertextStore;
import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * 业务记录读写接口：模拟"迁移期间仍有新读写进来"的在线流量。
 * 写入即加密入库，读取即按密文版本解密，迁移前后读到的明文一致。
 */
@RestController
@RequestMapping("/api/records")
public class RecordController {

    private final KeyManager keyManager;
    private final CiphertextStore store;

    public RecordController(KeyManager keyManager, CiphertextStore store) {
        this.keyManager = keyManager;
        this.store = store;
    }

    public record WriteRequest(String plaintext) {}
    public record WriteResponse(String id, int keyVersion) {}
    public record ReadResponse(String id, String plaintext, int keyVersion) {}

    @PutMapping("/{id}")
    public WriteResponse write(@PathVariable String id, @RequestBody WriteRequest request) {
        String ciphertext = keyManager.encrypt(request.plaintext().getBytes(StandardCharsets.UTF_8));
        store.put(id, ciphertext);
        return new WriteResponse(id, Ciphertext.parse(ciphertext).keyVersion());
    }

    @GetMapping("/{id}")
    public ReadResponse read(@PathVariable String id) {
        String ciphertext = store.read(id)
                .orElseThrow(() -> new KeyOperationException(FailureReason.KEY_NOT_FOUND,
                        "record " + id + " does not exist"));
        byte[] plaintext = keyManager.decrypt(ciphertext);
        return new ReadResponse(id, new String(plaintext, StandardCharsets.UTF_8),
                Ciphertext.parse(ciphertext).keyVersion());
    }

    @GetMapping
    public Map<String, Integer> list() {
        // 只暴露 id 与版本号，不暴露密文
        return store.snapshot().entrySet().stream()
                .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey,
                        e -> Ciphertext.parse(e.getValue()).keyVersion()));
    }
}
