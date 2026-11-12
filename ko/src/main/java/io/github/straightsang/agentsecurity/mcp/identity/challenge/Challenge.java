package io.github.straightsang.agentsecurity.mcp.identity.challenge;

import java.time.Instant;

/** 특정 Agent DID에 발급된 짧은 수명의 일회용 신원 증명값이다. */
public record Challenge(
        String challengeId,
        String agentDid,
        String value,
        Instant issuedAt,
        Instant expiresAt,
        boolean consumed) {

    public Challenge consume() {
        return new Challenge(challengeId, agentDid, value, issuedAt, expiresAt, true);
    }
}
