package io.github.straightsang.agentsecurity.mcp.domain;

import java.time.Instant;
import java.util.Map;

public record SecureToolRequest(
        String requestId,
        String actorDid,
        String tool,
        String action,
        String resource,
        Map<String, Object> arguments,
        Instant issuedAt,
        Instant expiresAt,
        String delegationToken,
        String signature) {
}

