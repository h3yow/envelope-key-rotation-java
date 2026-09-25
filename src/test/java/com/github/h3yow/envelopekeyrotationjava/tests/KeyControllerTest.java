package com.github.h3yow.envelopekeyrotationjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * REST 层验证：错误原因经 HTTP 响应可区分，且响应不含密钥材料。
 */
@SpringBootTest
@AutoConfigureMockMvc
class KeyControllerTest {

    private static final Logger log = LoggerFactory.getLogger(KeyControllerTest.class);

    @Autowired
    MockMvc mvc;

    private final ObjectMapper om = new ObjectMapper();

    private String encrypt(String plaintext) throws Exception {
        MvcResult r = mvc.perform(post("/api/keys/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"" + plaintext + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = om.readTree(r.getResponse().getContentAsString());
        log.info("http encrypt ok: keyVersion={}", body.get("keyVersion").asInt());
        return body.get("ciphertext").asText();
    }

    @Test
    void encryptDecryptRotateOverHttp() throws Exception {
        String ct = encrypt("hello-http");
        MvcResult r = mvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + ct + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode body = om.readTree(r.getResponse().getContentAsString());
        assertEquals("hello-http", body.get("plaintext").asText());

        MvcResult rot = mvc.perform(post("/api/keys/rotate"))
                .andExpect(status().isOk())
                .andReturn();
        int active = om.readTree(rot.getResponse().getContentAsString()).get("activeVersion").asInt();
        log.info("http rotate ok: activeVersion={}", active);

        // 历史密文仍可解密
        mvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + ct + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("hello-http"));
    }

    @Test
    void tamperedCiphertextReturnsDistinguishableReason() throws Exception {
        String ct = encrypt("to-be-tampered");
        String tampered = ct.substring(0, ct.length() - 2) + "AA";
        MvcResult r = mvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + tampered + "\"}"))
                .andExpect(status().isConflict())
                .andReturn();
        JsonNode body = om.readTree(r.getResponse().getContentAsString());
        log.info("http tamper rejected: reason={}", body.get("reason").asText());
        assertEquals("CIPHERTEXT_TAMPERED", body.get("reason").asText());
        assertFalse(body.has("plaintext"), "rejected response must not contain plaintext");
    }

    @Test
    void malformedCiphertextReturnsDistinguishableReason() throws Exception {
        mvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"garbage\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("CIPHERTEXT_MALFORMED"));
        mvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"EK1..AAAA\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("VERSION_MISSING"));
        log.info("http malformed inputs rejected with distinguishable reasons");
    }

    @Test
    void lifecycleOpsOverHttp() throws Exception {
        // 当前活跃版本不可直接销毁
        MvcResult list = mvc.perform(get("/api/keys")).andExpect(status().isOk()).andReturn();
        JsonNode versions = om.readTree(list.getResponse().getContentAsString());
        int active = -1;
        for (JsonNode v : versions) {
            if ("ACTIVE".equals(v.get("status").asText())) {
                active = v.get("version").asInt();
            }
            // 列表不得包含密钥材料字段
            assertFalse(v.has("keyMaterial"), "version view must not expose key material");
        }
        assertTrue(active > 0);
        log.info("http list ok: activeVersion={}", active);

        mvc.perform(post("/api/keys/" + active + "/destroy"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("ILLEGAL_STATE_TRANSITION"));

        mvc.perform(post("/api/keys/9999/deactivate"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("KEY_NOT_FOUND"));
        log.info("http lifecycle illegal ops rejected with distinguishable reasons");
    }
}
