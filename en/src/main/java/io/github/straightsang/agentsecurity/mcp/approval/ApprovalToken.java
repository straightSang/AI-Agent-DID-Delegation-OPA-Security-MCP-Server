package io.github.straightsang.agentsecurity.mcp.approval;

import java.time.Instant;

/* A one-time user approval token bound to one request hash, actor, and target. */
public record ApprovalToken(
        String approvalId,
        String requestHash,
        String actorDid,
        String target,
        String approverDid,
        Instant issuedAt,
        Instant expiresAt,
        String signature) {

    public ApprovalToken withSignature(String value) {
        return new ApprovalToken(
                approvalId, requestHash, actorDid, target, approverDid,
                issuedAt, expiresAt, value);
    }
}
