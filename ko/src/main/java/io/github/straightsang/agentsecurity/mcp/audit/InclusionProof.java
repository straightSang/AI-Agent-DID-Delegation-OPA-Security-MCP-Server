package io.github.straightsang.agentsecurity.mcp.audit;

import java.util.List;

/* 특정 이벤트가 체크포인트 root에 포함됨을 제3자가 다시 계산해 볼 수 있는 증명이다. */
public record InclusionProof(
        String checkpointId,
        long sequence,
        long leafIndex,
        long treeSize,
        String leafEventHash,
        List<String> auditPath,
        String merkleRoot) {
}
