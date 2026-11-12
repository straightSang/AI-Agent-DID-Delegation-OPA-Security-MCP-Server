package io.github.straightsang.agentsecurity.mcp.tools;

import io.github.straightsang.agentsecurity.mcp.approval.ApprovalToken;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.gateway.SecurityGateway;
import java.util.List;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

@Component
public class LabDocumentTools {
    private final SecurityGateway securityGateway;

    public LabDocumentTools(SecurityGateway securityGateway) {
        this.securityGateway = securityGateway;
    }

    @McpTool(name = "read_lab_document", description = "신원, 위임, 정책, 승인을 검증한 뒤 문서를 읽는다.")
    public String readLabDocument(
            @McpToolParam(description = "sandbox 상대 경로", required = true) String path,
            @McpToolParam(description = "현재 Agent의 did:key", required = true) String agentDid,
            @McpToolParam(description = "Challenge ID", required = true) String challengeId,
            @McpToolParam(description = "Challenge Ed25519 서명", required = true) String challengeSignature,
            @McpToolParam(description = "요청 일회용 ID", required = true) String requestId,
            @McpToolParam(description = "root부터 현재 Agent까지 위임 토큰", required = true)
                    List<DelegationToken> delegationChain,
            @McpToolParam(description = "고위험 요청의 사용자 승인 토큰", required = false)
                    ApprovalToken approvalToken) {
        return securityGateway.executeDocumentRead(
                path, agentDid, challengeId, challengeSignature,
                requestId, delegationChain, approvalToken);
    }
}
