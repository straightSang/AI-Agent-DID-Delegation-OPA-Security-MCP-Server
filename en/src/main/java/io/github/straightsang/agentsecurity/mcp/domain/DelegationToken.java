package io.github.straightsang.agentsecurity.mcp.domain;

import java.time.Instant;
import java.util.Set;

/*
 * A signed token representing permissions delegated to an Agent.
 *
 * tokenId: Unique ID of the current token
 * parentTokenId: Parent token ID; null for the initial root delegation
 * issuer: DID that delegated the permission
 * subject: DID of the Agent receiving the permission
 * audience: MCP server allowed to accept this token
 * actions/resources: Maximum delegated action and resource scope
 * issuedAt/expiresAt: Issue and expiration times
 * delegationDepth: Zero for the root delegation and incremented for each re-delegation
 * signature: Base64URL Ed25519 signature over the remaining fields using the issuer private key
 */
public record DelegationToken(
        String tokenId,
        String parentTokenId,
        String issuer,
        String subject,
        String audience,
        Set<String> actions,
        Set<String> resources,
        Instant issuedAt,
        Instant expiresAt,
        int delegationDepth,
        String signature) {

    public DelegationToken withSignature(String newSignature) {
        return new DelegationToken(
                tokenId, parentTokenId, issuer, subject, audience,
                actions, resources, issuedAt, expiresAt, delegationDepth, newSignature);
    }
}
