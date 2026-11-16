package io.github.straightsang.agentsecurity.mcp.approval;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/*
 * 위험 분류 결과를 실행 가능 여부로 강제하는 승인 보안 경계다.
 * REQUIRE_APPROVAL이면 (1) 한도형 승인 채널 또는 (2) 승인 토큰 M개 중 하나로 통과시킨다.
 * 둘 다 제시했는데 채널이 실패하면 토큰으로 조용히 넘어가지 않고 거부한다.
 */
@Component
public class ApprovalGateway {
    private final ApprovalService approvalService;
    private final MultiApprovalService multiApprovalService;
    private final ApprovalChannelService channelService;

    public ApprovalGateway(
            ApprovalService approvalService,
            MultiApprovalService multiApprovalService,
            ApprovalChannelService channelService) {
        this.approvalService = approvalService;
        this.multiApprovalService = multiApprovalService;
        this.channelService = channelService;
    }

    /* 기존 호출 방식(승인 토큰 1개)을 그대로 지원한다. */
    public void requireApprovalIfNeeded(
            RiskAssessment assessment,
            ApprovalToken approvalToken,
            String requestHash,
            String actorDid,
            String target) {
        requireApprovalIfNeeded(
                assessment, approvalToken, List.of(), null, requestHash, actorDid, target, target);
    }

    /* 감사 원장에 남길 승인 근거 문자열을 돌려준다. 승인이 필요 없으면 빈 문자열이다. */
    public String requireApprovalIfNeeded(
            RiskAssessment assessment,
            ApprovalToken approvalToken,
            List<ApprovalToken> additionalTokens,
            ApprovalChannelGrant channelGrant,
            String requestHash,
            String actorDid,
            String action,
            String target) {
        switch (assessment.decision()) {
            case ALLOW, ALLOW_LOG -> {
                return "";
            }
            case DENY -> throw new AccessDeniedException(
                    "위험도가 너무 높아 사용자 승인으로도 실행할 수 없습니다.");
            case REQUIRE_APPROVAL -> {
                if (channelGrant != null) {
                    if (assessment.riskLevel() != RiskLevel.HIGH) {
                        throw new AccessDeniedException("승인 채널은 HIGH 위험 요청에만 사용할 수 있습니다.");
                    }
                    return channelService.useOne(channelGrant, actorDid, action, target, requestHash).note();
                }
                List<ApprovalToken> tokens = new ArrayList<>();
                if (approvalToken != null) tokens.add(approvalToken);
                if (additionalTokens != null) tokens.addAll(additionalTokens);
                int required = multiApprovalService.requiredApprovals(assessment);
                if (required == 1 && tokens.size() == 1) {
                    approvalService.verifyAndConsume(tokens.getFirst(), requestHash, actorDid, target);
                    return "approvals:1";
                }
                multiApprovalService.verifyAndConsumeAll(tokens, required, requestHash, actorDid, target);
                return "approvals:" + tokens.size();
            }
        }
        return "";
    }
}
