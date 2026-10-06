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

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 批量迁移与版本治理的端到端（HTTP）验证。
 *
 * <p>所有记录 id 带唯一前缀，避免与同上下文的其他测试类互相干扰。</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
class MigrationApiTest {

    private static final Logger log = LoggerFactory.getLogger(MigrationApiTest.class);

    @Autowired
    MockMvc mvc;

    private final ObjectMapper om = new ObjectMapper();
    private final String prefix = "api-" + UUID.randomUUID() + "-";

    private String saveRecord(String id, String plaintext) throws Exception {
        MvcResult r = mvc.perform(post("/api/records")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"id\":\"" + id + "\",\"plaintext\":\"" + plaintext + "\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = om.readTree(r.getResponse().getContentAsString());
        return body.get("ciphertext").asText();
    }

    private JsonNode postJson(String path, String json) throws Exception {
        MvcResult r = mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                        .content(json == null ? "{}" : json))
                .andExpect(status().isOk()).andReturn();
        return om.readTree(r.getResponse().getContentAsString());
    }

    @Test
    void saveReadMigrateReadOverHttp() throws Exception {
        // 3 条老数据（当前活跃版本加密）
        for (int i = 0; i < 3; i++) {
            saveRecord(prefix + "old-" + i, "secret-" + i);
        }
        // 轮换：老数据留在旧版本
        JsonNode rotated = postJson("/api/keys/rotate", "{}");
        int newActive = rotated.get("activeVersion").asInt();
        log.info("HTTP 场景: 轮换后 activeVersion={}", newActive);

        // 迁移前读取：明文正确，版本是旧版本
        MvcResult before = mvc.perform(get("/api/records/" + prefix + "old-1"))
                .andExpect(status().isOk()).andReturn();
        JsonNode beforeBody = om.readTree(before.getResponse().getContentAsString());
        assertEquals("secret-1", beforeBody.get("plaintext").asText());
        int oldVersion = beforeBody.get("keyVersion").asInt();
        assertTrue(oldVersion < newActive);

        // 全量迁移（单片）
        JsonNode migration = postJson("/api/migrations",
                "{\"maxBatch\":10}");
        log.info("HTTP 场景: 迁移响应 targetVersion={}, processed={}, skipped={}, hasMore={}",
                migration.get("targetVersion").asInt(), migration.get("processed").asInt(),
                migration.get("skipped").asInt(), migration.get("hasMore").asBoolean());
        assertEquals(newActive, migration.get("targetVersion").asInt());
        // 全局存储里至少这 3 条被处理（processed 可能包含其他测试遗留，这里用子集接口更精确，
        // 但本上下文此前没有迁移调用，所以恰为本前缀记录数）
        assertTrue(migration.get("processed").asInt() >= 3);

        // 迁移后读取：明文不变，版本变为最新
        for (int i = 0; i < 3; i++) {
            mvc.perform(get("/api/records/" + prefix + "old-" + i))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.plaintext").value("secret-" + i))
                    .andExpect(jsonPath("$.keyVersion").value(newActive));
        }

        // 再迁一次：幂等，这些记录全部跳过（processed 必为 0，因为没有新增旧版本数据）
        JsonNode rerun = postJson("/api/migrations", "{\"maxBatch\":10}");
        log.info("HTTP 场景: 重复迁移 -> processed={}, skipped={}",
                rerun.get("processed").asInt(), rerun.get("skipped").asInt());
        assertEquals(0, rerun.get("processed").asInt());
    }

    @Test
    void pagedMigrationResumesOverHttp() throws Exception {
        // 用显式 ids 限定本用例的数据，确保计数精确
        int n = 7;
        StringBuilder idsJson = new StringBuilder("[");
        for (int i = 0; i < n; i++) {
            saveRecord(prefix + "page-" + i, "p" + i);
            if (i > 0) {
                idsJson.append(",");
            }
            idsJson.append("\"").append(prefix).append("page-").append(i).append("\"");
        }
        idsJson.append("]");
        JsonNode rotated = postJson("/api/keys/rotate", "{}");
        int target = rotated.get("activeVersion").asInt();

        JsonNode page1 = postJson("/api/migrations",
                "{\"ids\":" + idsJson + ",\"maxBatch\":3}");
        assertEquals(3, page1.get("processed").asInt());
        assertTrue(page1.get("hasMore").asBoolean());
        String cursor = page1.get("nextCursor").asText();

        JsonNode page2 = postJson("/api/migrations",
                "{\"ids\":" + idsJson + ",\"maxBatch\":3,\"cursor\":\"" + cursor + "\"}");
        assertEquals(3, page2.get("processed").asInt());
        assertEquals(0, page2.get("skipped").asInt(), "续跑不得重做已处理记录");
        String cursor2 = page2.get("nextCursor").asText();

        JsonNode page3 = postJson("/api/migrations",
                "{\"ids\":" + idsJson + ",\"maxBatch\":3,\"cursor\":\"" + cursor2 + "\"}");
        assertEquals(1, page3.get("processed").asInt());
        assertFalse(page3.get("hasMore").asBoolean());
        assertTrue(page3.get("nextCursor").isNull());
        log.info("HTTP 场景: 分片续跑 3+3+1 收敛, targetVersion={}", target);

        for (int i = 0; i < n; i++) {
            mvc.perform(get("/api/records/" + prefix + "page-" + i))
                    .andExpect(jsonPath("$.plaintext").value("p" + i))
                    .andExpect(jsonPath("$.keyVersion").value(target));
        }
    }

    @Test
    void destroyReferencedVersionRejectedOverHttp() throws Exception {
        String id = prefix + "guarded";
        saveRecord(id, "guarded-data");
        int sourceVersion = om.readTree(mvc.perform(get("/api/records/" + id)).andReturn()
                .getResponse().getContentAsString()).get("keyVersion").asInt();

        // 无论当前处于什么生命周期状态，只要仍被引用：销毁统一 409 + KEY_STILL_REFERENCED
        mvc.perform(post("/api/keys/" + sourceVersion + "/destroy"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("KEY_STILL_REFERENCED"));
        log.info("HTTP 场景: 销毁仍被引用的 v{} -> 409 KEY_STILL_REFERENCED", sourceVersion);

        // 响应体不含明文
        MvcResult rejected = mvc.perform(post("/api/keys/" + sourceVersion + "/destroy"))
                .andExpect(status().isConflict()).andReturn();
        assertFalse(rejected.getResponse().getContentAsString().contains("guarded-data"));
    }
}
