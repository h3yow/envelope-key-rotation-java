package com.github.h3yow.envelopekeyrotationjava.web;

import com.github.h3yow.envelopekeyrotationjava.crypto.CryptoService;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyManager;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST facade. Responses expose key versions and statuses only — never key
 * material or derived secrets.
 */
@RestController
@RequestMapping("/api")
public class CryptoController {

    private final CryptoService cryptoService;

    public CryptoController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    public record EncryptRequest(String plaintext) {
    }

    public record EncryptResponse(String ciphertext, int version) {
    }

    public record DecryptRequest(String ciphertext) {
    }

    public record DecryptResponse(String plaintext, int version) {
    }

    public record RotateRequest(Integer expectedVersion) {
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@RequestBody EncryptRequest request) {
        String ciphertext = cryptoService.encrypt(request.plaintext());
        return new EncryptResponse(ciphertext, cryptoService.getActiveVersion());
    }

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@RequestBody DecryptRequest request) {
        String plaintext = cryptoService.decrypt(request.ciphertext());
        return new DecryptResponse(plaintext, cryptoService.getActiveVersion());
    }

    @PostMapping("/keys/rotate")
    public KeyManager.RotationResult rotate(@RequestBody(required = false) RotateRequest request) {
        return cryptoService.rotate(request == null ? null : request.expectedVersion());
    }

    @PostMapping("/keys/{version}/disable")
    public void disable(@PathVariable int version) {
        cryptoService.disableKey(version);
    }

    @PostMapping("/keys/{version}/destroy")
    public void destroy(@PathVariable int version) {
        cryptoService.destroyKey(version);
    }

    @GetMapping("/keys")
    public List<KeyManager.KeyInfo> listKeys() {
        return cryptoService.listKeys();
    }
}
