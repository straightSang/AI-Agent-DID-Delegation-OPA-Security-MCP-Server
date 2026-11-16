package io.github.straightsang.agentsecurity.mcp.groundtruth;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.testsupport.Fixtures;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PermissionGraphServiceTest {
    private Fixtures fx;
    private KeyPair orchestratorKeys;
    private KeyPair workerKeys;
    private String orchestratorDid;
    private String workerDid;
    private DelegationToken root;
    private DelegationToken child;
    private PermissionGraphService service;

    @BeforeEach
    void setUp() {
        fx = new Fixtures();
        orchestratorKeys = fx.newKeys();
        workerKeys = fx.newKeys();
        orchestratorDid = fx.didOf(orchestratorKeys);
        workerDid = fx.didOf(workerKeys);
        root = fx.tokenService.issueRoot(
                fx.userDid, orchestratorDid, "agent-security-mcp",
                Set.of("calculator_add", "read_lab_document"), Set.of("calculator", "docs/a.txt"),
                Instant.now().plusSeconds(600), fx.userKeys.getPrivate());
        child = fx.tokenService.delegate(
                root, workerDid, Set.of("calculator_add"), Set.of("calculator"),
                Instant.now().plusSeconds(300), orchestratorKeys.getPrivate());
        service = new PermissionGraphService(
                fx.ledger, fx.delegationProperties, fx.revocationService, GroundTruthProperties.defaults());
    }

    @Test
    void effectivePermissionIsIntersectionOfWholeChain() {
        service.ingestChain(List.of(root, child), "r1");
        List<PermissionGraph.EffectiveGrant> grants = service.effectiveGrants(workerDid, Instant.now());
        assertThat(grants).hasSize(1);
        assertThat(grants.getFirst().actions()).containsExactly("calculator_add");
        assertThat(grants.getFirst().rootIssuer()).isEqualTo(fx.userDid);
        assertThat(grants.getFirst().chainTokenIds()).containsExactly(root.tokenId(), child.tokenId());
        assertThat(service.agentsWithAccess("read_lab_document", null, Instant.now()))
                .containsExactly(orchestratorDid);
        assertThat(service.downstreamAgents(orchestratorDid)).containsExactly(workerDid);
    }

    @Test
    void ingestRecordsEachTokenOnceAndRebuildsIdenticalGraphFromLedger() {
        assertThat(service.ingestChain(List.of(root, child), "r1")).hasSize(2);
        assertThat(service.ingestChain(List.of(root, child), "r2")).isEmpty();
        assertThat(fx.ledger.snapshot().stream()
                .filter(event -> event.action().equals(PermissionGraphService.ACTION_DELEGATION)).count())
                .isEqualTo(2L);

        PermissionGraphService restarted = new PermissionGraphService(
                fx.ledger, fx.delegationProperties, fx.revocationService, GroundTruthProperties.defaults());
        assertThat(restarted.tokenCount()).isEqualTo(2);
        assertThat(restarted.effectiveGrants(workerDid, Instant.now())).hasSize(1);
        assertThat(service.matchesLedger()).isTrue();
        assertThat(fx.ledger.verifyAll()).isTrue();
    }

    @Test
    void revokingParentRevokesDescendantsAndRemovesEffectivePermission() {
        service.ingestChain(List.of(root, child), "r1");
        List<String> revoked = service.revokeCascade(root.tokenId(), "rev-1", "test");
        assertThat(revoked).containsExactly(root.tokenId(), child.tokenId());
        assertThat(service.effectiveGrants(workerDid, Instant.now())).isEmpty();
        assertThat(fx.revocationService.isRevoked(child.tokenId())).isTrue();

        PermissionGraphService restarted = new PermissionGraphService(
                fx.ledger, fx.delegationProperties, fx.revocationService, GroundTruthProperties.defaults());
        assertThat(restarted.isRevoked(child.tokenId())).isTrue();
    }

    @Test
    void independentCheckFindsEscalationThatAVerifierBugCouldMiss() {
        // 검증기를 거치지 않고 부모보다 넓은 자식이 원장에 들어온 상황을 만든다.
        service.ingestChain(List.of(root), "r1");
        DelegationToken wider = new DelegationToken(
                "forged-1", root.tokenId(), orchestratorDid, workerDid, "agent-security-mcp",
                Set.of("calculator_add", "delete_everything"), Set.of("calculator", "secrets/all"),
                root.issuedAt(), root.expiresAt(), 1, "sig");
        service.ingestChain(List.of(wider), "r2");
        List<PermissionGraph.Finding> findings = service.findingsForChain(List.of(wider), Instant.now());
        assertThat(findings.stream().anyMatch(f -> f.type().equals("ESCALATION")
                && f.severity() == PermissionGraph.Severity.HIGH)).isTrue();
        // 실효 권한은 체인 교집합이라 확대된 부분이 실제 권한이 되지는 않는다.
        assertThat(service.effectiveGrants(workerDid, Instant.now()).getFirst().actions())
                .containsExactly("calculator_add");
    }

    @Test
    void flagsWildcardSensitiveLongLivedAndDeepDelegations() {
        DelegationToken broad = fx.tokenService.issueRoot(
                fx.userDid, orchestratorDid, "agent-security-mcp",
                Set.of("*"), Set.of("personal/data", "calculator"),
                Instant.now().plusSeconds(3 * 24 * 3600), fx.userKeys.getPrivate());
        service.ingestChain(List.of(broad), "r1");
        List<String> types = service.findingsForChain(List.of(broad), Instant.now())
                .stream().map(PermissionGraph.Finding::type).toList();
        assertThat(types).contains("BROAD_SCOPE", "SENSITIVE_SCOPE", "LONG_LIVED");
    }

    @Test
    void encodingRoundTripPreservesEveryField() {
        PermissionGraph.TokenNode node = PermissionGraph.TokenNode.from(child);
        PermissionGraph.TokenNode decoded = PermissionGraphService.decodeToken(
                child.tokenId(), PermissionGraphService.encodeToken(node));
        assertThat(decoded).isEqualTo(node);
        PermissionGraph.TokenNode rootNode = PermissionGraph.TokenNode.from(root);
        assertThat(PermissionGraphService.decodeToken(
                root.tokenId(), PermissionGraphService.encodeToken(rootNode))).isEqualTo(rootNode);
    }
}
