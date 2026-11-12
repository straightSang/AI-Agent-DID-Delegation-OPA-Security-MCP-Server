package io.github.straightsang.agentsecurity.mcp.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class AuditLogger {

    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);

    public void logAllowed(String requestId, String actor, String tool) {
        log.info("security_decision requestId={} actor={} tool={} decision=ALLOW",
                requestId, actor, tool);
    }

    public void logDenied(String requestId, String actor, String tool, String reason) {
        log.warn("security_decision requestId={} actor={} tool={} decision=DENY reason={}",
                requestId, actor, tool, reason);
    }
}

