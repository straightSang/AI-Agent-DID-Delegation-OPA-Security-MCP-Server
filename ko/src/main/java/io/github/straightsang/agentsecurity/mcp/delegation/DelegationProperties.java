package io.github.straightsang.agentsecurity.mcp.delegation;

import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

/* 위임 토큰을 받을 MCP 서버 이름, 최대 위임 깊이, 신뢰할 최초 발급자를 설정한다. */
@ConfigurationProperties(prefix = "security.delegation")
public record DelegationProperties(
        String audience,
        int maxDepth,
        Set<String> trustedIssuers) {

    public DelegationProperties {
        trustedIssuers = trustedIssuers == null ? Set.of() : Set.copyOf(trustedIssuers);
    }

    public boolean isTrustedIssuer(String issuer) {
        return issuer != null && trustedIssuers.contains(issuer);
    }
}
