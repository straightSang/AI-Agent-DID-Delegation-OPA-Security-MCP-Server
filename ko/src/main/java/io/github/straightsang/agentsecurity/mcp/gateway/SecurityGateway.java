package io.github.straightsang.agentsecurity.mcp.gateway;

import io.github.straightsang.agentsecurity.mcp.approval.ApprovalChannelGrant;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalGateway;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalToken;
import io.github.straightsang.agentsecurity.mcp.approval.PolicyOutcome;
import io.github.straightsang.agentsecurity.mcp.approval.RiskAssessment;
import io.github.straightsang.agentsecurity.mcp.approval.RiskClassifier;
import io.github.straightsang.agentsecurity.mcp.audit.AuditLogger;
import io.github.straightsang.agentsecurity.mcp.audit.SignedAuditLedger;
import io.github.straightsang.agentsecurity.mcp.domain.AuthenticatedIdentity;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.groundtruth.GroundTruthGuard;
import io.github.straightsang.agentsecurity.mcp.identity.AgentProofVerifier;
import io.github.straightsang.agentsecurity.mcp.opa.DelegationContext;
import io.github.straightsang.agentsecurity.mcp.opa.OpaAuthorizationService;
import io.github.straightsang.agentsecurity.mcp.opa.OpaDecision;
import io.github.straightsang.agentsecurity.mcp.opa.OpaInput;
import io.github.straightsang.agentsecurity.mcp.security.CanonicalRequestHashService;
import io.github.straightsang.agentsecurity.mcp.security.DelegationVerifier;
import io.github.straightsang.agentsecurity.mcp.security.ReplayProtectionService;
import io.github.straightsang.agentsecurity.mcp.security.RequestRateLimiter;
import io.github.straightsang.agentsecurity.mcp.service.CalculatorService;
import io.github.straightsang.agentsecurity.mcp.service.LabDocumentService;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

/*
 * 신원 -> 속도 제한 -> 위임 -> Replay -> Ground Truth -> OPA -> 위험 승인 -> 실행 -> 서명 원장 순서를 강제한다.
 * 요청 해시에는 위임 체인의 tokenId와 audience까지 묶어, 승인 뒤에 체인을 바꿔치기해도 승인이 통하지 않게 한다.
 */
@Service
public class SecurityGateway {
    private final AgentProofVerifier agentProofVerifier;
    private final RequestRateLimiter rateLimiter;
    private final DelegationVerifier delegationVerifier;
    private final ReplayProtectionService replayProtectionService;
    private final GroundTruthGuard groundTruthGuard;
    private final OpaAuthorizationService opaAuthorizationService;
    private final RiskClassifier riskClassifier;
    private final ApprovalGateway approvalGateway;
    private final CanonicalRequestHashService requestHashService;
    private final SignedAuditLedger signedAuditLedger;
    private final CalculatorService calculatorService;
    private final LabDocumentService labDocumentService;
    private final AuditLogger auditLogger;

    public SecurityGateway(
            AgentProofVerifier agentProofVerifier,
            RequestRateLimiter rateLimiter,
            DelegationVerifier delegationVerifier,
            ReplayProtectionService replayProtectionService,
            GroundTruthGuard groundTruthGuard,
            OpaAuthorizationService opaAuthorizationService,
            RiskClassifier riskClassifier,
            ApprovalGateway approvalGateway,
            CanonicalRequestHashService requestHashService,
            SignedAuditLedger signedAuditLedger,
            CalculatorService calculatorService,
            LabDocumentService labDocumentService,
            AuditLogger auditLogger) {
        this.agentProofVerifier = agentProofVerifier;
        this.rateLimiter = rateLimiter;
        this.delegationVerifier = delegationVerifier;
        this.replayProtectionService = replayProtectionService;
        this.groundTruthGuard = groundTruthGuard;
        this.opaAuthorizationService = opaAuthorizationService;
        this.riskClassifier = riskClassifier;
        this.approvalGateway = approvalGateway;
        this.requestHashService = requestHashService;
        this.signedAuditLedger = signedAuditLedger;
        this.calculatorService = calculatorService;
        this.labDocumentService = labDocumentService;
        this.auditLogger = auditLogger;
    }

    public int executeAddition(
            int a, int b,
            String agentDid, String challengeId, String challengeSignature,
            String requestId, List<DelegationToken> delegationChain,
            ApprovalToken approvalToken) {
        return executeAddition(a, b, agentDid, challengeId, challengeSignature, requestId,
                delegationChain, approvalToken, null, null);
    }

    public int executeAddition(
            int a, int b,
            String agentDid, String challengeId, String challengeSignature,
            String requestId, List<DelegationToken> delegationChain,
            ApprovalToken approvalToken, List<ApprovalToken> additionalApprovals,
            ApprovalChannelGrant channelGrant) {
        String action = "calculator_add";
        String resource = "calculator";
        Map<String, Object> arguments = Map.of("a", a, "b", b);
        return run(action, resource, arguments, agentDid, challengeId, challengeSignature,
                requestId, delegationChain, approvalToken, additionalApprovals, channelGrant,
                () -> calculatorService.add(a, b));
    }

    public String executeDocumentRead(
            String path,
            String agentDid, String challengeId, String challengeSignature,
            String requestId, List<DelegationToken> delegationChain,
            ApprovalToken approvalToken) {
        return executeDocumentRead(path, agentDid, challengeId, challengeSignature, requestId,
                delegationChain, approvalToken, null, null);
    }

    public String executeDocumentRead(
            String path,
            String agentDid, String challengeId, String challengeSignature,
            String requestId, List<DelegationToken> delegationChain,
            ApprovalToken approvalToken, List<ApprovalToken> additionalApprovals,
            ApprovalChannelGrant channelGrant) {
        String action = "read_lab_document";
        Map<String, Object> arguments = Map.of("path", path);
        return run(action, path, arguments, agentDid, challengeId, challengeSignature,
                requestId, delegationChain, approvalToken, additionalApprovals, channelGrant,
                () -> labDocumentService.read(path));
    }

    /* 두 도구가 공유하는 처리 순서다. 어떤 단계에서든 예외가 나면 DENY로 원장에 남기고 다시 던진다. */
    private <T> T run(
            String action, String resource, Map<String, Object> arguments,
            String agentDid, String challengeId, String challengeSignature,
            String requestId, List<DelegationToken> chain,
            ApprovalToken approvalToken, List<ApprovalToken> additionalApprovals,
            ApprovalChannelGrant channelGrant, java.util.function.Supplier<T> execution) {
        String requestHash = requestHashService.hashRequest(
                agentDid, action, resource, arguments, requestId, resource,
                tokenIds(chain), audience(chain));
        try {
            VerifiedRequest verified = verifyRequest(
                    agentDid, challengeId, challengeSignature, requestId, chain, action, resource);
            GroundTruthGuard.Outcome groundTruth = groundTruthGuard.inspect(
                    requestId, action, chain, arguments, resource);
            requireOpaAllow(opaInput(verified, action, resource, arguments));
            RiskAssessment assessment = groundTruthGuard.applyEscalation(
                    riskClassifier.assess(action, resource, arguments, resource), groundTruth);
            String approvalNote = approvalGateway.requireApprovalIfNeeded(
                    assessment, approvalToken, additionalApprovals, channelGrant,
                    requestHash, agentDid, action, resource);
            T result = execution.get();
            recordDecision(requestId, agentDid, action, resource, "ALLOW",
                    join("EXECUTED", approvalNote, groundTruth.note()),
                    requestHash, requestHashService.hashResponse(result));
            return result;
        } catch (RuntimeException exception) {
            recordDecision(requestId, agentDid, action, resource, "DENY", exception.getMessage(),
                    requestHash, requestHashService.hashResponse(exception.getMessage()));
            throw exception;
        }
    }

    private VerifiedRequest verifyRequest(
            String agentDid, String challengeId, String challengeSignature,
            String requestId, List<DelegationToken> chain,
            String action, String resource) {
        AuthenticatedIdentity identity = agentProofVerifier.verify(
                agentDid, challengeId, challengeSignature);
        rateLimiter.check(identity.did());
        DelegationToken leaf = delegationVerifier.verifyChain(
                chain, identity.did(), action, resource);
        replayProtectionService.checkAndConsume(requestId);
        return new VerifiedRequest(identity, chain.getFirst().issuer(), leaf);
    }

    private OpaInput opaInput(
            VerifiedRequest verified, String action, String resource, Map<String, Object> arguments) {
        return new OpaInput(
                verified.identity().did(), true, true, action, resource, arguments,
                DelegationContext.from(verified.rootIssuer(), verified.leafToken()));
    }

    private void requireOpaAllow(OpaInput input) {
        OpaDecision decision = opaAuthorizationService.authorize(input);
        if (decision.outcome() == PolicyOutcome.DENY) {
            throw new AccessDeniedException(decision.reason());
        }
    }

    private List<String> tokenIds(List<DelegationToken> chain) {
        if (chain == null) return List.of();
        return chain.stream().map(token -> token == null ? "" : token.tokenId()).toList();
    }

    private String audience(List<DelegationToken> chain) {
        if (chain == null || chain.isEmpty() || chain.getLast() == null) return "";
        return chain.getLast().audience();
    }

    private String join(String... parts) {
        return String.join("; ", java.util.Arrays.stream(parts).filter(part -> part != null && !part.isBlank()).toList());
    }

    private void recordDecision(
            String requestId, String actor, String action, String resource,
            String decision, String reason, String requestHash, String responseHash) {
        signedAuditLedger.append(
                requestId, actor, action, resource, decision, reason, requestHash, responseHash);
        if ("ALLOW".equals(decision)) auditLogger.logAllowed(requestId, actor, action);
        else auditLogger.logDenied(requestId, actor, action, reason);
    }

    private record VerifiedRequest(
            AuthenticatedIdentity identity, String rootIssuer, DelegationToken leafToken) {
    }
}
