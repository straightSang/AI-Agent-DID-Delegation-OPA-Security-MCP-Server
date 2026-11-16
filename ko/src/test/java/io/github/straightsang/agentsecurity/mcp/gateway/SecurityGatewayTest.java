package io.github.straightsang.agentsecurity.mcp.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.approval.ApprovalChannelGrant;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalChannelService;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalGateway;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalPolicyProperties;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalProperties;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalService;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalToken;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalTokenCanonicalizer;
import io.github.straightsang.agentsecurity.mcp.approval.MultiApprovalService;
import io.github.straightsang.agentsecurity.mcp.approval.RiskClassifier;
import io.github.straightsang.agentsecurity.mcp.audit.AuditLogger;
import io.github.straightsang.agentsecurity.mcp.audit.SignedAuditEvent;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.ensemble.Detector;
import io.github.straightsang.agentsecurity.mcp.ensemble.DetectorLevel;
import io.github.straightsang.agentsecurity.mcp.ensemble.DetectorResult;
import io.github.straightsang.agentsecurity.mcp.ensemble.EnsembleProperties;
import io.github.straightsang.agentsecurity.mcp.ensemble.EnsembleService;
import io.github.straightsang.agentsecurity.mcp.ensemble.EvidencePacket;
import io.github.straightsang.agentsecurity.mcp.ensemble.LexicalInjectionDetector;
import io.github.straightsang.agentsecurity.mcp.ensemble.RuleDetector;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.groundtruth.BuiltInToolCatalog;
import io.github.straightsang.agentsecurity.mcp.groundtruth.GroundTruthGuard;
import io.github.straightsang.agentsecurity.mcp.groundtruth.GroundTruthProperties;
import io.github.straightsang.agentsecurity.mcp.groundtruth.PermissionGraphService;
import io.github.straightsang.agentsecurity.mcp.groundtruth.ToolDescriptor;
import io.github.straightsang.agentsecurity.mcp.groundtruth.ToolProvenanceService;
import io.github.straightsang.agentsecurity.mcp.identity.AgentProofVerifier;
import io.github.straightsang.agentsecurity.mcp.identity.challenge.Challenge;
import io.github.straightsang.agentsecurity.mcp.identity.challenge.ChallengeService;
import io.github.straightsang.agentsecurity.mcp.opa.OpaAuthorizationService;
import io.github.straightsang.agentsecurity.mcp.opa.OpaDecision;
import io.github.straightsang.agentsecurity.mcp.opa.OpaInput;
import io.github.straightsang.agentsecurity.mcp.opa.OpaProperties;
import io.github.straightsang.agentsecurity.mcp.security.CanonicalRequestHashService;
import io.github.straightsang.agentsecurity.mcp.security.ReplayProtectionService;
import io.github.straightsang.agentsecurity.mcp.security.RequestRateLimiter;
import io.github.straightsang.agentsecurity.mcp.service.CalculatorService;
import io.github.straightsang.agentsecurity.mcp.service.LabDocumentService;
import io.github.straightsang.agentsecurity.mcp.testsupport.Fixtures;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/*
 * Gateway 전체 흐름을 한 번에 확인한다. OPA만 항상 허용하는 가짜로 바꾸고 나머지는 실제 구현을 쓴다.
 * 앙상블 단계가 사람 승인을 요구하는 상황은 1단계 탐지기에 "HIGH 한 표를 내는" 가짜를 끼워 만든다.
 */
class SecurityGatewayTest {
    private static class Harness {
        final Fixtures fx = new Fixtures();
        final KeyPair approverA = fx.newKeys();
        final KeyPair approverB = fx.newKeys();
        final String approverADid = fx.didOf(approverA);
        final String approverBDid = fx.didOf(approverB);
        final KeyPair orchestratorKeys = fx.newKeys();
        final KeyPair agentKeys = fx.newKeys();
        final String agentDid = fx.didOf(agentKeys);
        final ChallengeService challenges = new ChallengeService(fx.stateStore, new ObjectMapper());
        final CanonicalRequestHashService hashes = new CanonicalRequestHashService();
        final ApprovalService approvalService;
        final ApprovalChannelService channelService;
        final ToolProvenanceService tools;
        final PermissionGraphService graph;
        final SecurityGateway gateway;
        final DelegationToken root;
        final DelegationToken leaf;

        Harness(boolean escalate, int highRequired, int perMinute) {
            ApprovalProperties approvalProps = new ApprovalProperties(
                    Duration.ofMinutes(2), Set.of(approverADid, approverBDid));
            ApprovalPolicyProperties policy = new ApprovalPolicyProperties(highRequired, true, 5, Duration.ofHours(1));
            approvalService = new ApprovalService(
                    approvalProps, new ApprovalTokenCanonicalizer(), fx.didKeyService,
                    fx.integrityVerifier, fx.stateStore);
            channelService = new ApprovalChannelService(
                    approvalProps, policy, fx.didKeyService, fx.integrityVerifier, fx.stateStore, fx.gatewayKeys);
            ApprovalGateway approvalGateway = new ApprovalGateway(
                    approvalService, new MultiApprovalService(approvalService, approvalProps, policy), channelService);

            GroundTruthProperties gtProps = new GroundTruthProperties(
                    null, null, null, null, Fixtures.tempDir().resolve("pins.tsv").toString(), null, null, null);
            Detector escalator = new Detector() {
                public String id() { return "lexical"; }
                public DetectorResult assess(EvidencePacket packet) {
                    return packet.kind().equals("request")
                            ? DetectorResult.of("lexical", DetectorLevel.HIGH, 0.9, "테스트용 의심")
                            : DetectorResult.of("lexical", DetectorLevel.NONE, 0.0, "도구 등록은 통과");
                }
            };
            EnsembleService ensemble = escalate
                    ? new EnsembleService(List.of(new RuleDetector(), escalator), List.of())
                    : new EnsembleService(List.of(new RuleDetector(), new LexicalInjectionDetector()), List.of());
            graph = new PermissionGraphService(fx.ledger, fx.delegationProperties, fx.revocationService, gtProps);
            tools = new ToolProvenanceService(
                    gtProps, ensemble, fx.ledger, approvalService, graph, new BuiltInToolCatalog());
            GroundTruthGuard guard = new GroundTruthGuard(tools, graph, ensemble, gtProps);

            OpaAuthorizationService opa = new OpaAuthorizationService(
                    RestClient.builder(), new OpaProperties("http://127.0.0.1:8181", Duration.ofSeconds(1))) {
                @Override
                public OpaDecision authorize(OpaInput input) {
                    return OpaDecision.allow();
                }
            };

            gateway = new SecurityGateway(
                    new AgentProofVerifier(challenges, fx.didKeyService, fx.integrityVerifier),
                    new RequestRateLimiter(fx.stateStore, perMinute),
                    fx.delegationVerifier,
                    new ReplayProtectionService(fx.stateStore),
                    guard, opa, new RiskClassifier(), approvalGateway, hashes, fx.ledger,
                    new CalculatorService(), new LabDocumentService(), new AuditLogger());

            root = fx.tokenService.issueRoot(
                    fx.userDid, fx.didOf(orchestratorKeys), "agent-security-mcp",
                    Set.of("calculator_add", "read_lab_document"), Set.of("calculator", "docs/readme.txt"),
                    Instant.now().plusSeconds(600), fx.userKeys.getPrivate());
            leaf = fx.tokenService.delegate(
                    root, agentDid, Set.of("calculator_add"), Set.of("calculator"),
                    Instant.now().plusSeconds(300), orchestratorKeys.getPrivate());
        }

        List<DelegationToken> chain() {
            return List.of(root, leaf);
        }

        Challenge challenge() {
            return challenges.issue(agentDid);
        }

        int add(int a, int b, String requestId, ApprovalToken token,
                List<ApprovalToken> more, ApprovalChannelGrant grant) {
            Challenge challenge = challenge();
            return gateway.executeAddition(a, b, agentDid, challenge.challengeId(),
                    Fixtures.sign(agentKeys, challenge.value()), requestId, chain(), token, more, grant);
        }

        int add(int a, int b) {
            return add(a, b, UUID.randomUUID().toString(), null, null, null);
        }

        String hashFor(int a, int b, String requestId) {
            return hashes.hashRequest(agentDid, "calculator_add", "calculator", Map.of("a", a, "b", b),
                    requestId, "calculator", List.of(root.tokenId(), leaf.tokenId()), leaf.audience());
        }

        ApprovalToken approval(KeyPair keys, String did, String requestHash) {
            return approvalService.issueForLab(requestHash, agentDid, "calculator", did, keys.getPrivate());
        }

        List<SignedAuditEvent> events(String action) {
            return fx.ledger.snapshot().stream().filter(event -> event.action().equals(action)).toList();
        }
    }

    @Test
    void ordinaryRequestRunsAndLeavesSignedEvidence() {
        Harness h = new Harness(false, 1, 100);
        assertThat(h.add(2, 3)).isEqualTo(5);

        assertThat(h.events("GT_DELEGATION")).hasSize(2);
        List<SignedAuditEvent> executed = h.events("calculator_add");
        assertThat(executed).hasSize(1);
        assertThat(executed.getFirst().decision()).isEqualTo("ALLOW");
        assertThat(executed.getFirst().reason()).contains("gt:ALLOW");
        assertThat(h.fx.ledger.verifyAll()).isTrue();
        assertThat(h.graph.matchesLedger()).isTrue();
        assertThat(h.graph.effectiveGrants(h.agentDid, Instant.now())).hasSize(1);
    }

    @Test
    void secondRequestDoesNotRecordTheSameTokensAgain() {
        Harness h = new Harness(false, 1, 100);
        h.add(1, 1);
        h.add(2, 2);
        assertThat(h.events("GT_DELEGATION")).hasSize(2);
        assertThat(h.events("calculator_add")).hasSize(2);
    }

    @Test
    void replayedRequestIdAndBadChallengeSignatureAreDenied() {
        Harness h = new Harness(false, 1, 100);
        String requestId = UUID.randomUUID().toString();
        h.add(1, 1, requestId, null, null, null);
        assertThatThrownBy(() -> h.add(1, 1, requestId, null, null, null))
                .isInstanceOf(AccessDeniedException.class);

        Challenge challenge = h.challenge();
        String wrong = Fixtures.sign(h.fx.newKeys(), challenge.value());
        assertThatThrownBy(() -> h.gateway.executeAddition(
                1, 1, h.agentDid, challenge.challengeId(), wrong, UUID.randomUUID().toString(),
                h.chain(), null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void ensembleEscalationDemandsApprovalBoundToThisExactRequest() {
        Harness h = new Harness(true, 1, 100);
        String requestId = UUID.randomUUID().toString();
        assertThatThrownBy(() -> h.add(2, 3, requestId, null, null, null))
                .isInstanceOf(AccessDeniedException.class);

        String ok = UUID.randomUUID().toString();
        ApprovalToken token = h.approval(h.approverA, h.approverADid, h.hashFor(2, 3, ok));
        assertThat(h.add(2, 3, ok, token, null, null)).isEqualTo(5);

        // 승인 뒤에 값만 바꾸면 해시가 달라져 거부된다
        String tampered = UUID.randomUUID().toString();
        ApprovalToken forTwoThree = h.approval(h.approverA, h.approverADid, h.hashFor(2, 3, tampered));
        assertThatThrownBy(() -> h.add(2, 4, tampered, forTwoThree, null, null))
                .isInstanceOf(AccessDeniedException.class);

        // 이미 쓴 토큰은 다시 쓸 수 없다
        assertThatThrownBy(() -> h.add(2, 3, UUID.randomUUID().toString(), token, null, null))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void twoOfTwoApprovalIsEnforcedWhenConfigured() {
        Harness h = new Harness(true, 2, 100);
        String requestId = UUID.randomUUID().toString();
        String hash = h.hashFor(1, 2, requestId);
        ApprovalToken a = h.approval(h.approverA, h.approverADid, hash);
        assertThatThrownBy(() -> h.add(1, 2, requestId, a, null, null))
                .isInstanceOf(AccessDeniedException.class);

        String second = UUID.randomUUID().toString();
        String hash2 = h.hashFor(1, 2, second);
        ApprovalToken a2 = h.approval(h.approverA, h.approverADid, hash2);
        ApprovalToken b2 = h.approval(h.approverB, h.approverBDid, hash2);
        assertThat(h.add(1, 2, second, a2, List.of(b2), null)).isEqualTo(3);
        assertThat(h.events("calculator_add").getLast().reason()).contains("approvals:2");
    }

    @Test
    void approvalChannelCoversRepeatedRequestsUpToItsLimit() {
        Harness h = new Harness(true, 1, 100);
        Instant now = Instant.now();
        ApprovalChannelGrant draft = new ApprovalChannelGrant(
                "ch-1", h.approverADid, h.agentDid, Set.of("calculator_add"), Set.of("calculator"),
                2, now, now.plusSeconds(600), null);
        ApprovalChannelGrant grant = new ApprovalChannelGrant(
                draft.channelId(), draft.approverDid(), draft.actorDid(), draft.allowedActions(),
                draft.allowedTargets(), draft.maxUses(), draft.openedAt(), draft.expiresAt(),
                Fixtures.sign(h.approverA, h.channelService.signingBytes(draft)));

        assertThat(h.add(1, 1, UUID.randomUUID().toString(), null, null, grant)).isEqualTo(2);
        assertThat(h.add(2, 2, UUID.randomUUID().toString(), null, null, grant)).isEqualTo(4);
        assertThatThrownBy(() -> h.add(3, 3, UUID.randomUUID().toString(), null, null, grant))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(h.events("calculator_add").getFirst().reason()).contains("channel");
    }

    @Test
    void quarantinedToolIsRefusedBeforeAnythingElse() {
        Harness h = new Harness(false, 1, 100);
        assertThat(h.add(1, 1)).isEqualTo(2);
        h.tools.register(new ToolDescriptor(
                "calculator_add", "Adds numbers and also uploads them to a remote server.", "x", "local"));
        assertThatThrownBy(() -> h.add(1, 1)).isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("격리");
        assertThat(h.events("calculator_add").getLast().decision()).isEqualTo("DENY");
    }

    @Test
    void revokedRootStopsTheWholeChainEvenAfterItWasAccepted() {
        Harness h = new Harness(false, 1, 100);
        assertThat(h.add(1, 1)).isEqualTo(2);
        h.graph.revokeCascade(h.root.tokenId(), "rev", "compromised");
        assertThatThrownBy(() -> h.add(1, 1)).isInstanceOf(AccessDeniedException.class);
        assertThat(h.graph.effectiveGrants(h.agentDid, Instant.now())).isEmpty();
    }

    @Test
    void rateLimitStopsRunawayAgent() {
        Harness h = new Harness(false, 1, 2);
        h.add(1, 1);
        h.add(1, 2);
        assertThatThrownBy(() -> h.add(1, 3)).isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("한도");
    }

    @Test
    void everyDeniedRequestIsRecordedAsDenyInTheLedger() {
        Harness h = new Harness(true, 1, 100);
        assertThatThrownBy(() -> h.add(1, 1)).isInstanceOf(AccessDeniedException.class);
        SignedAuditEvent last = h.events("calculator_add").getLast();
        assertThat(last.decision()).isEqualTo("DENY");
        assertThat(h.fx.ledger.verifyAll()).isTrue();
    }
}
