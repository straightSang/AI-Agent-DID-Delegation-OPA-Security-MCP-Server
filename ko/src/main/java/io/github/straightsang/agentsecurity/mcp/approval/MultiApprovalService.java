package io.github.straightsang.agentsecurity.mcp.approval;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;

/*
 * 고위험 요청에 서로 다른 승인자 M명의 서명을 요구한다(M-of-N).
 * - 같은 승인자의 중복 서명은 한 번으로 센다. 중복이 섞여 있으면 거부한다.
 * - 요청한 Agent 자신은 승인자가 될 수 없다(직무 분리).
 * - 모든 토큰을 먼저 검증한 뒤에 사용 처리한다. 하나라도 틀리면 어떤 토큰도 소모하지 않는다.
 */
@Service
public class MultiApprovalService {
    private final ApprovalService approvalService;
    private final ApprovalProperties approvalProperties;
    private final ApprovalPolicyProperties policy;

    public MultiApprovalService(
            ApprovalService approvalService,
            ApprovalProperties approvalProperties,
            ApprovalPolicyProperties policy) {
        this.approvalService = approvalService;
        this.approvalProperties = approvalProperties;
        this.policy = policy;
    }

    /* 위험 등급별로 필요한 승인 수를 돌려준다. HIGH만 설정값을 따르고 나머지는 1이다. */
    public int requiredApprovals(RiskAssessment assessment) {
        return assessment.riskLevel() == RiskLevel.HIGH ? policy.highRequiredApprovals() : 1;
    }

    public void verifyAndConsumeAll(
            List<ApprovalToken> tokens,
            int required,
            String requestHash,
            String actorDid,
            String target) {
        if (tokens == null || tokens.isEmpty()) {
            throw new AccessDeniedException("사용자 승인 토큰이 필요합니다.");
        }
        if (required > approvalProperties.trustedApprovers().size()) {
            throw new AccessDeniedException("신뢰된 승인자 수가 필요한 승인 수보다 적게 설정되어 있습니다.");
        }
        Set<String> approvers = new HashSet<>();
        for (ApprovalToken token : tokens) {
            if (token == null) throw new AccessDeniedException("사용자 승인 토큰이 필요합니다.");
            if (token.approverDid() != null && token.approverDid().equals(actorDid)) {
                throw new AccessDeniedException("요청한 Agent는 자기 요청을 승인할 수 없습니다.");
            }
            if (!approvers.add(token.approverDid())) {
                throw new AccessDeniedException("같은 승인자의 중복 승인은 한 번만 인정됩니다.");
            }
        }
        if (approvers.size() < required) {
            throw new AccessDeniedException(
                    "필요한 승인 수 " + required + "명을 채우지 못했습니다. 현재 " + approvers.size() + "명입니다.");
        }
        for (ApprovalToken token : tokens) {
            approvalService.verifyOnly(token, requestHash, actorDid, target);
        }
        for (ApprovalToken token : tokens) {
            approvalService.consume(token);
        }
    }
}
