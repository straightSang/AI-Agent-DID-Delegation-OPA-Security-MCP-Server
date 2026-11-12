package io.github.straightsang.agentsecurity.mcp.approval;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import org.springframework.stereotype.Component;

/* Approval security boundary that enforces the risk-classification result. */
@Component
public class ApprovalGateway {
    private final ApprovalService approvalService;

    public ApprovalGateway(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    public void requireApprovalIfNeeded(
            RiskAssessment assessment,
            ApprovalToken approvalToken,
            String requestHash,
            String actorDid,
            String target) {
        switch (assessment.decision()) {
            case ALLOW, ALLOW_LOG -> {
                return;
            }
            case REQUIRE_APPROVAL -> approvalService.verifyAndConsume(
                    approvalToken, requestHash, actorDid, target);
            case DENY -> throw new AccessDeniedException(
                    "위험도가 너무 높아 사용자 승인으로도 실행할 수 없습니다.");
        }
    }
}
