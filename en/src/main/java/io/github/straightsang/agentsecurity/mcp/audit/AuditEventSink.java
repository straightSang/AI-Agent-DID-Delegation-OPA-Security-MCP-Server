package io.github.straightsang.agentsecurity.mcp.audit;

/** Production extension point for replicating ledger entries to a central store. */
public interface AuditEventSink {
    void store(AuditLedgerEntry entry);
}
