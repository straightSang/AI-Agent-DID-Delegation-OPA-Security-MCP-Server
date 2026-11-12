package io.github.straightsang.agentsecurity.mcp.audit;

public interface LedgerAnchorService {
    String anchor(LedgerCheckpoint checkpoint);
}
