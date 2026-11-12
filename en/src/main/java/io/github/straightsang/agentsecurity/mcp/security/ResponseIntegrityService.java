package io.github.straightsang.agentsecurity.mcp.security;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import io.github.straightsang.agentsecurity.mcp.crypto.SigningService;
import io.github.straightsang.agentsecurity.mcp.domain.ToolExecutionResult;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.stereotype.Service;

/** Binds an MCP result to its request hash and server signature. */
@Service
public class ResponseIntegrityService {
    private final SigningService signingService;
    private final ObjectMapper mapper;

    public ResponseIntegrityService(SigningService signingService, ObjectMapper objectMapper) {
        this.signingService = signingService;
        this.mapper = objectMapper;
    }

    public <T> ToolExecutionResult<T> sign(
            String requestId, String decision, String reason, T result,
            String requestHash, String ledgerEventHash) {
        Instant executedAt = Instant.now();
        try {
            String responseHash = hashResult(result);
            String signedEnvelope = String.join("\n", requestId, decision, reason,
                    requestHash, responseHash, ledgerEventHash, executedAt.toString());
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    signingService.sign(signedEnvelope.getBytes(StandardCharsets.UTF_8)));
            return new ToolExecutionResult<>(
                    requestId, decision, reason, result, requestHash, responseHash,
                    ledgerEventHash, executedAt, signingService.algorithm(), signature);
        } catch (RuntimeException exception) {
            throw new IllegalStateException("MCP 응답 서명에 실패했습니다.", exception);
        }
    }

    public String hashResult(Object result) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(mapper.writeValueAsBytes(result)));
        } catch (JacksonException | NoSuchAlgorithmException exception) {
            throw new IllegalStateException("응답 해시를 만들지 못했습니다.", exception);
        }
    }
}
