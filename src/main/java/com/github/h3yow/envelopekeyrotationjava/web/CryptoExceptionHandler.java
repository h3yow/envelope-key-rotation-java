package com.github.h3yow.envelopekeyrotationjava.web;

import com.github.h3yow.envelopekeyrotationjava.crypto.FailureReason;
import com.github.h3yow.envelopekeyrotationjava.crypto.KeyOperationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 将 KeyOperationException 映射为携带失败原因的 HTTP 响应。
 * 响应中只包含失败原因与版本号，不包含密钥材料、明文或密文内容。
 */
@RestControllerAdvice
public class CryptoExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(CryptoExceptionHandler.class);

    @ExceptionHandler(KeyOperationException.class)
    public ResponseEntity<Map<String, Object>> handle(KeyOperationException ex) {
        FailureReason reason = ex.getReason();
        HttpStatus status = switch (reason) {
            case VERSION_MISSING, CIPHERTEXT_MALFORMED -> HttpStatus.BAD_REQUEST;
            case CIPHERTEXT_TAMPERED, KEY_DISABLED, KEY_DESTROYED,
                 ILLEGAL_STATE_TRANSITION, NO_ACTIVE_KEY,
                 KEY_STILL_REFERENCED, VERSION_LIMIT_EXCEEDED -> HttpStatus.CONFLICT;
            case KEY_NOT_FOUND -> HttpStatus.NOT_FOUND;
        };
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", reason.name());
        body.put("message", ex.getMessage());
        if (ex.getKeyVersion() != null) {
            body.put("keyVersion", ex.getKeyVersion());
        }
        log.warn("request rejected: reason={}, keyVersion={}", reason, ex.getKeyVersion());
        return ResponseEntity.status(status).body(body);
    }
}
