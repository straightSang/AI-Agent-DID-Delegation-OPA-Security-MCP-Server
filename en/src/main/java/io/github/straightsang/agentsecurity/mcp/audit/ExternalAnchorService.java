package io.github.straightsang.agentsecurity.mcp.audit;

/* Pluggable boundary for publishing a Merkle root to an external system such as OpenTimestamps. */
public interface ExternalAnchorService {
    String anchor(String merkleRoot);
}
