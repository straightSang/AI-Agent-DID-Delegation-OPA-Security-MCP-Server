package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;

/** Merkle root를 외부 저장소에 고정한 결과다. */
public record LedgerCheckpoint(
        String checkpointId,
        String instanceId,
        long firstSequence,
        long lastSequence,
        String merkleRoot,
        Instant createdAt,
        String signatureAlgorithm,
        String signature,
        String anchorReceipt) {
    public LedgerCheckpoint withReceipt(String receipt) {
        return new LedgerCheckpoint(
                checkpointId, instanceId, firstSequence, lastSequence, merkleRoot,
                createdAt, signatureAlgorithm, signature, receipt);
    }
}
