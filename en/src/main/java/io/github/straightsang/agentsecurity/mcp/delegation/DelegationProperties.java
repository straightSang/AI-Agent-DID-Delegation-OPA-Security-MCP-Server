package io.github.straightsang.agentsecurity.mcp.delegation;

import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

/* Configures the MCP audience, maximum delegation depth, and trusted root issuers. */
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
