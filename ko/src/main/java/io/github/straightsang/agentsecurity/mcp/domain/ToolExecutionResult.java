package io.github.straightsang.agentsecurity.mcp.domain;

import java.time.Instant;

/** 결과와 요청·응답 해시, 서버 서명을 함께 반환해 전송 후 조작을 검출한다. */
public record ToolExecutionResult<T>(
        String requestId,
        String decision,
        String reason,
        T result,
        String requestHash,
        String responseHash,
        String ledgerEventHash,
        Instant executedAt,
        String signatureAlgorithm,
        String signature) {
}

