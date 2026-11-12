package io.github.straightsang.agentsecurity.mcp.identity.challenge;

import java.time.Instant;

/** Short-lived, one-time identity proof issued to a specific Agent DID. */
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
