package io.github.straightsang.agentsecurity.mcp.tools;

import io.github.straightsang.agentsecurity.mcp.approval.ApprovalChannelGrant;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalToken;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.gateway.SecurityGateway;
import java.util.List;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

@Component
public class CalculatorTools {
    private final SecurityGateway securityGateway;

    public CalculatorTools(SecurityGateway securityGateway) {
        this.securityGateway = securityGateway;
    }

    @McpTool(name = "calculator_add", description = "신원, 위임, 정책, 승인을 검증한 뒤 두 정수를 더한다.")
    public int add(
            @McpToolParam(description = "첫 번째 정수", required = true) int a,
            @McpToolParam(description = "두 번째 정수", required = true) int b,
            @McpToolParam(description = "현재 Agent의 did:key", required = true) String agentDid,
            @McpToolParam(description = "Challenge ID", required = true) String challengeId,
            @McpToolParam(description = "Challenge Ed25519 서명", required = true) String challengeSignature,
            @McpToolParam(description = "요청 일회용 ID", required = true) String requestId,
            @McpToolParam(description = "root부터 현재 Agent까지 위임 토큰", required = true)
                    List<DelegationToken> delegationChain,
            @McpToolParam(description = "고위험 요청의 사용자 승인 토큰", required = false)
                    ApprovalToken approvalToken,
            @McpToolParam(description = "M-of-N 승인에서 추가로 받은 승인 토큰", required = false)
                    List<ApprovalToken> additionalApprovalTokens,
            @McpToolParam(description = "한도형 사전 승인(승인 채널). 승인 토큰 대신 사용", required = false)
                    ApprovalChannelGrant approvalChannelGrant) {
        return securityGateway.executeAddition(
                a, b, agentDid, challengeId, challengeSignature,
                requestId, delegationChain, approvalToken,
                additionalApprovalTokens, approvalChannelGrant);
    }
}
