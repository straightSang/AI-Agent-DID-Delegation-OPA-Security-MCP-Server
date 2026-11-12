package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;
import java.util.List;

/* 일정 구간의 감사 이벤트와 Merkle root, 외부 앵커 영수증을 표현한다. */
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
