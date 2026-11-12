package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;

/* Audit event binding request, response, policy decision, and previous hash with a Gateway signature. */
public record SignedAuditEvent(
        long sequence,
        Instant timestamp,
        String requestId,
        String actorDid,
        String action,
        String resource,
        String decision,
        String reason,
        String requestHash,
        String responseHash,
        String previousEventHash,
        String eventHash,
        String gatewayDid,
        String signature) {

    public SignedAuditEvent withProof(String hash, String gateway, String newSignature) {
        return new SignedAuditEvent(
                sequence, timestamp, requestId, actorDid, action, resource, decision, reason,
                requestHash, responseHash, previousEventHash, hash, gateway, newSignature);
    }
}
