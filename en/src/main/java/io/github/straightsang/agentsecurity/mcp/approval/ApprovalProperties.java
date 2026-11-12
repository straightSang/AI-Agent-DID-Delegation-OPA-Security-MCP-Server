package io.github.straightsang.agentsecurity.mcp.approval;

import java.time.Duration;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.approval")
public record ApprovalProperties(Duration tokenTtl, Set<String> trustedApprovers) {
    public ApprovalProperties {
        tokenTtl = tokenTtl == null ? Duration.ofMinutes(2) : tokenTtl;
        trustedApprovers = trustedApprovers == null ? Set.of() : Set.copyOf(trustedApprovers);
    }

    public boolean isTrustedApprover(String did) {
        return did != null && trustedApprovers.contains(did);
    }
}
