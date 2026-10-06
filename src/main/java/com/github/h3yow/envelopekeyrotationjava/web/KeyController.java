package com.github.h3yow.envelopekeyrotationjava.web;

import com.github.h3yow.envelopekeyrotationjava.crypto.Ciphertext;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import com.github.h3yow.envelopekeyrotationjava.crypto.MigrationReport;
import com.github.h3yow.envelopekeyrotationjava.crypto.MigrationService;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * 密钥生命周期与加解密的 REST 接口。
 */
@RestController
@RequestMapping("/api/keys")
public class KeyController {

    private final KeyManager keyManager;
    private final MigrationService migrationService;

    public KeyController(KeyManager keyManager, MigrationService migrationService) {
        this.keyManager = keyManager;
        this.migrationService = migrationService;
    }

    public record EncryptRequest(String plaintext) {}
    public record EncryptResponse(String ciphertext, int keyVersion) {}
    public record DecryptRequest(String ciphertext) {}
    public record DecryptResponse(String plaintext, int keyVersion) {}
    public record RotateResponse(int activeVersion) {}
    public record KeyVersionView(int version, String status, String createdAt) {}

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@RequestBody EncryptRequest request) {
        String ciphertext = keyManager.encrypt(request.plaintext().getBytes(StandardCharsets.UTF_8));
        return new EncryptResponse(ciphertext, Ciphertext.parse(ciphertext).keyVersion());
    }

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@RequestBody DecryptRequest request) {
        byte[] plaintext = keyManager.decrypt(request.ciphertext());
        int version = Ciphertext.parse(request.ciphertext()).keyVersion();
        return new DecryptResponse(new String(plaintext, StandardCharsets.UTF_8), version);
    }

    @PostMapping("/rotate")
    public RotateResponse rotate() {
        return new RotateResponse(keyManager.rotate());
    }

    @PostMapping("/migrate")
    public MigrationReport migrate() {
        return migrationService.migrateAll();
    }

    @PostMapping("/{version}/deactivate")
    public Map<String, Object> deactivate(@PathVariable int version) {
        keyManager.deactivate(version);
        return Map.of("version", version, "status", "DISABLED");
    }

    @PostMapping("/{version}/destroy")
    public Map<String, Object> destroy(@PathVariable int version) {
        keyManager.destroy(version);
        return Map.of("version", version, "status", "DESTROYED");
    }

    @GetMapping
    public List<KeyVersionView> list() {
        return keyManager.listVersions().stream()
                .map(kv -> new KeyVersionView(kv.getVersion(), kv.getStatus().name(), kv.getCreatedAt().toString()))
                .toList();
    }
}
