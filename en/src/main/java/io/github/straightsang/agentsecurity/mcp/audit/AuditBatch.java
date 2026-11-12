package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;
import java.util.List;

/* Represents an audit batch, its Merkle root, and external-anchor receipt. */
public record AuditBatch(
        String batchId,
        Instant createdAt,
        List<String> eventHashes,
        String merkleRoot,
        String anchorReceipt) {

    public AuditBatch withReceipt(String receipt) {
        return new AuditBatch(batchId, createdAt, eventHashes, merkleRoot, receipt);
    }
}
