package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;

/*
 * 원장의 앞 treeSize개 이벤트를 Merkle root 하나로 고정하고 Gateway 키로 서명한 체크포인트다.
 * headEventHash는 treeSize번째 이벤트의 해시이며, 원장 꼬리 절단과 재작성을 탐지하는 기준이 된다.
 */
public record SignedCheckpoint(
        String checkpointId,
        long treeSize,
        String merkleRoot,
        String headEventHash,
        Instant createdAt,
        String gatewayDid,
        String signature,
        String anchorReceipt) {
}
