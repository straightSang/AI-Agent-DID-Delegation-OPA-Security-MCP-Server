package io.github.straightsang.agentsecurity.mcp.audit;

/* Merkle root를 OpenTimestamps 같은 외부 시스템에 게시하는 교체 가능한 경계다. */
public interface ExternalAnchorService {
    String anchor(String merkleRoot);
}
