package io.github.straightsang.agentsecurity.mcp.audit;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!aws")
public class LocalAuditEventSink implements AuditEventSink {
    @Override public void store(AuditLedgerEntry entry) {
        // Locally, use only the in-memory AuditLedgerService chain and file checkpoints.
    }
}
