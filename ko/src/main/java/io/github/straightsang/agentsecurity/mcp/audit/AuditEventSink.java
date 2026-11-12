package io.github.straightsang.agentsecurity.mcp.audit;

/** 원장 항목을 중앙 저장소에 복제하는 운영 확장점이다. */
public interface AuditEventSink {
    void store(AuditLedgerEntry entry);
}
