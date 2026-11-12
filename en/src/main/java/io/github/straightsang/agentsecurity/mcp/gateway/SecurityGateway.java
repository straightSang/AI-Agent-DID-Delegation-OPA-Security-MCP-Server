package io.github.straightsang.agentsecurity.mcp.gateway;

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
import io.github.straightsang.agentsecurity.mcp.identity.AgentProofVerifier;
import io.github.straightsang.agentsecurity.mcp.opa.DelegationContext;
import io.github.straightsang.agentsecurity.mcp.opa.OpaAuthorizationService;
import io.github.straightsang.agentsecurity.mcp.opa.OpaDecision;
import io.github.straightsang.agentsecurity.mcp.opa.OpaInput;
import io.github.straightsang.agentsecurity.mcp.security.CanonicalRequestHashService;
import io.github.straightsang.agentsecurity.mcp.security.DelegationVerifier;
import io.github.straightsang.agentsecurity.mcp.security.ReplayProtectionService;
import io.github.straightsang.agentsecurity.mcp.service.CalculatorService;
import io.github.straightsang.agentsecurity.mcp.service.LabDocumentService;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

/* Enforces identity, delegation, replay protection, OPA, risk approval, execution, and signed-ledger order. */
@Service
public class SecurityGateway {
    private final AgentProofVerifier agentProofVerifier;
    private final DelegationVerifier delegationVerifier;
    private final ReplayProtectionService replayProtectionService;
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
            DelegationVerifier delegationVerifier,
            ReplayProtectionService replayProtectionService,
            OpaAuthorizationService opaAuthorizationService,
            RiskClassifier riskClassifier,
            ApprovalGateway approvalGateway,
            CanonicalRequestHashService requestHashService,
            SignedAuditLedger signedAuditLedger,
            CalculatorService calculatorService,
            LabDocumentService labDocumentService,
            AuditLogger auditLogger) {
        this.agentProofVerifier = agentProofVerifier;
        this.delegationVerifier = delegationVerifier;
        this.replayProtectionService = replayProtectionService;
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
        String action = "calculator_add";
        String resource = "calculator";
        Map<String, Object> arguments = Map.of("a", a, "b", b);
        String requestHash = requestHashService.hashRequest(
                agentDid, action, resource, arguments, requestId, resource);
        try {
            VerifiedRequest verified = verifyRequest(
                    agentDid, challengeId, challengeSignature, requestId,
                    delegationChain, action, resource);
            requireOpaAllow(opaInput(verified, action, resource, arguments));
            requireRiskApproval(action, resource, arguments, approvalToken, requestHash, agentDid);
            int result = calculatorService.add(a, b);
            recordDecision(requestId, agentDid, action, resource, "ALLOW", "EXECUTED",
                    requestHash, requestHashService.hashResponse(result));
            return result;
        } catch (RuntimeException exception) {
            recordDecision(requestId, agentDid, action, resource, "DENY", exception.getMessage(),
                    requestHash, requestHashService.hashResponse(exception.getMessage()));
            throw exception;
        }
    }

    public String executeDocumentRead(
            String path,
            String agentDid, String challengeId, String challengeSignature,
            String requestId, List<DelegationToken> delegationChain,
            ApprovalToken approvalToken) {
        String action = "read_lab_document";
        String resource = path;
        Map<String, Object> arguments = Map.of("path", path);
        String requestHash = requestHashService.hashRequest(
                agentDid, action, resource, arguments, requestId, resource);
        try {
            VerifiedRequest verified = verifyRequest(
                    agentDid, challengeId, challengeSignature, requestId,
                    delegationChain, action, resource);
            requireOpaAllow(opaInput(verified, action, resource, arguments));
            requireRiskApproval(action, resource, arguments, approvalToken, requestHash, agentDid);
            String result = labDocumentService.read(path);
            recordDecision(requestId, agentDid, action, resource, "ALLOW", "EXECUTED",
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

    private void requireRiskApproval(
            String action, String resource, Map<String, Object> arguments,
            ApprovalToken token, String requestHash, String actorDid) {
        RiskAssessment assessment = riskClassifier.assess(action, resource, arguments, resource);
        approvalGateway.requireApprovalIfNeeded(
                assessment, token, requestHash, actorDid, resource);
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
