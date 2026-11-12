package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;

/** Ledger entry signing the previous, request, and response hashes to detect later modification. */
public record AuditLedgerEntry(
        String instanceId,
        long sequence,
        String previousHash,
        String requestHash,
        String responseHash,
        String actorDid,
        String action,
        String resource,
        String decision,
        Instant timestamp,
        String eventHash,
        String signatureAlgorithm,
        String signature) {
}
