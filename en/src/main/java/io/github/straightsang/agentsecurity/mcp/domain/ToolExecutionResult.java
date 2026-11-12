package io.github.straightsang.agentsecurity.mcp.domain;

import java.time.Instant;

/** Returns the result with request/response hashes and a server signature to detect transit tampering. */
public record ToolExecutionResult<T>(
        String requestId,
        String decision,
        String reason,
        T result,
        String requestHash,
        String responseHash,
        String ledgerEventHash,
        Instant executedAt,
        String signatureAlgorithm,
        String signature) {
}

