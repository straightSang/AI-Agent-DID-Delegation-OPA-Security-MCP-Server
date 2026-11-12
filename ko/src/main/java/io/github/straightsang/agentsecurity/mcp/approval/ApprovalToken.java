package io.github.straightsang.agentsecurity.mcp.approval;

import java.time.Instant;

/* 특정 요청 해시와 Actor, 대상에만 사용할 수 있는 일회용 사용자 승인 토큰이다. */
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
