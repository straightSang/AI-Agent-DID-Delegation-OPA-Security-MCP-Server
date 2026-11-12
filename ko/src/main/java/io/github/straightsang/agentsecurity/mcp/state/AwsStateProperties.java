package io.github.straightsang.agentsecurity.mcp.state;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.aws")
public record AwsStateProperties(
        String stateTable,
        String auditTable,
        String anchorBucket,
        String kmsKeyId,
        int anchorRetentionDays) {
}
