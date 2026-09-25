package com.github.h3yow.envelopekeyrotationjava.web;

import com.github.h3yow.envelopekeyrotationjava.crypto.CryptoErrorCode;
import com.github.h3yow.envelopekeyrotationjava.crypto.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps {@link CryptoException} to HTTP responses with a distinguishable error
 * code. Responses and logs contain only the code and a safe message — never
 * key material, plaintext, or ciphertext bytes.
 */
@RestControllerAdvice
public class CryptoExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(CryptoExceptionHandler.class);

    public record ErrorResponse(String code, String message) {
    }

    @ExceptionHandler(CryptoException.class)
    public ResponseEntity<ErrorResponse> handle(CryptoException ex) {
        HttpStatus status = switch (ex.getCode()) {
            case MALFORMED_CIPHERTEXT, VERSION_MISSING, INVALID_ARGUMENT -> HttpStatus.BAD_REQUEST;
            case UNKNOWN_KEY_VERSION -> HttpStatus.NOT_FOUND;
            case INTEGRITY_CHECK_FAILED, KEY_DISABLED, KEY_DESTROYED,
                 ILLEGAL_STATE_TRANSITION, NO_ACTIVE_KEY -> HttpStatus.CONFLICT;
        };
        CryptoErrorCode code = ex.getCode();
        log.info("crypto operation rejected: code={} reason={}", code, ex.getMessage());
        return ResponseEntity.status(status).body(new ErrorResponse(code.name(), ex.getMessage()));
    }
}
