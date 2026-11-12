package io.github.straightsang.agentsecurity.mcp.approval;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.stereotype.Service;

/** Canonicalizes the full request so argument or delegation-chain changes after approval alter the hash. */
@Service
public class RequestFingerprintService {
    private final ObjectMapper mapper;

    public RequestFingerprintService(ObjectMapper objectMapper) {
        this.mapper = objectMapper;
    }

    public String hash(
            String requestId, String actorDid, String action, String resource,
            Map<String, Object> arguments, List<DelegationToken> chain) {
        Map<String, Object> canonical = new TreeMap<>();
        canonical.put("requestId", requestId);
        canonical.put("actorDid", actorDid);
        canonical.put("action", action);
        canonical.put("resource", resource);
        canonical.put("arguments", new TreeMap<>(arguments));
        canonical.put("delegationTokenIds", chain.stream().map(DelegationToken::tokenId).toList());
        try {
            byte[] bytes = mapper.writeValueAsString(canonical).getBytes(StandardCharsets.UTF_8);
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (JacksonException | NoSuchAlgorithmException exception) {
            throw new IllegalStateException("요청 해시를 만들지 못했습니다.", exception);
        }
    }
}
