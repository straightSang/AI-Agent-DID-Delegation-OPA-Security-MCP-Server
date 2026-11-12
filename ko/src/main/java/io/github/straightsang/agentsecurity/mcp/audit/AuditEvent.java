package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;

public record AuditEvent(
        Instant timestamp,
        String requestId,
        String actor,
        String tool,
        String decision,
        String reason) {
}

