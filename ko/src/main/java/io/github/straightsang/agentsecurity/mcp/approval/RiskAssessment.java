package io.github.straightsang.agentsecurity.mcp.approval;

import java.util.List;

/* 승인창에 보여줄 실행 내용, 전달 대상, 위험 설명을 함께 보관한다. */
public record RiskAssessment(
        RiskLevel riskLevel,
        DecisionType decision,
        String executionSummary,
        String target,
        List<String> risks) {
}
