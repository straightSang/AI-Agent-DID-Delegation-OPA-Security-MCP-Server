package io.github.straightsang.agentsecurity.mcp.domain;

import java.time.Instant;
import java.util.Set;

/*
 * Agent에게 위임한 권한을 나타내는 서명 토큰이다.
 *
 * tokenId: 현재 토큰의 고유 ID
 * parentTokenId: 부모 토큰 ID. 최초 위임(root)은 null
 * issuer: 권한을 위임한 DID
 * subject: 권한을 위임받은 Agent DID
 * audience: 이 토큰을 사용할 수 있는 MCP 서버
 * actions/resources: 위임받은 행동과 리소스의 최대 범위
 * issuedAt/expiresAt: 발급 시각과 만료 시각
 * delegationDepth: 최초 위임은 0, 다시 위임할 때마다 1 증가
 * signature: issuer 개인키로 나머지 필드를 Ed25519 서명한 Base64URL 값
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
