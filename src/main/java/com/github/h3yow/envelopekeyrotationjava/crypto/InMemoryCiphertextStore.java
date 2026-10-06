package com.github.h3yow.envelopekeyrotationjava.crypto;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 进程内密文存储：基于 ConcurrentHashMap，compareAndSet 即 map.replace 的原子语义。
 */
@Component
public class InMemoryCiphertextStore implements CiphertextStore {

    private final ConcurrentHashMap<String, String> data = new ConcurrentHashMap<>();

    @Override
    public Optional<String> read(String id) {
        return Optional.ofNullable(data.get(id));
    }

    @Override
    public boolean compareAndSet(String id, String expected, String newValue) {
        return data.replace(id, expected, newValue);
    }

    @Override
    public void put(String id, String ciphertext) {
        data.put(id, ciphertext);
    }

    @Override
    public Map<String, String> snapshot() {
        return Map.copyOf(data);
    }
}
