package io.github.straightsang.agentsecurity.mcp.opa;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.opa")
public record OpaProperties(String url, Duration timeout) {
}

