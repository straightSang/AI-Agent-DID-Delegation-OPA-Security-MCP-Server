package io.github.straightsang.agentsecurity.mcp.approval;

import java.util.List;

/* Stores the execution summary, target, and risk explanation shown in the approval dialog. */
public record RiskAssessment(
        RiskLevel riskLevel,
        DecisionType decision,
        String executionSummary,
        String target,
        List<String> risks) {
}
