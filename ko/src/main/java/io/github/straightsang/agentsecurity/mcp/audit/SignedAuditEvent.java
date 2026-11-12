package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;

/* 요청과 응답, 정책 결정, 이전 이벤트 해시를 Gateway 서명으로 묶은 감사 이벤트다. */
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
