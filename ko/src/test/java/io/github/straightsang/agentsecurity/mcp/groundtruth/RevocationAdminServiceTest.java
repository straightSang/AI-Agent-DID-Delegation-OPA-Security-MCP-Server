package io.github.straightsang.agentsecurity.mcp.groundtruth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.testsupport.Fixtures;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RevocationAdminServiceTest {
    private Fixtures fx;
    private KeyPair orchestratorKeys;
    private KeyPair workerKeys;
    private DelegationToken root;
    private DelegationToken child;
    private PermissionGraphService graph;
    private RevocationAdminService admin;

    @BeforeEach
    void setUp() {
        fx = new Fixtures();
        orchestratorKeys = fx.newKeys();
        workerKeys = fx.newKeys();
        root = fx.tokenService.issueRoot(
                fx.userDid, fx.didOf(orchestratorKeys), "agent-security-mcp",
                Set.of("calculator_add"), Set.of("calculator"),
                Instant.now().plusSeconds(600), fx.userKeys.getPrivate());
        child = fx.tokenService.delegate(
                root, fx.didOf(workerKeys), Set.of("calculator_add"), Set.of("calculator"),
                Instant.now().plusSeconds(300), orchestratorKeys.getPrivate());
        graph = new PermissionGraphService(
                fx.ledger, fx.delegationProperties, fx.revocationService, GroundTruthProperties.defaults());
        graph.ingestChain(List.of(root, child), "r1");
        admin = new RevocationAdminService(
                graph, fx.didKeyService, fx.integrityVerifier, fx.stateStore);
    }

    private String sign(KeyPair keys, String tokenId, Instant at) {
        return Fixtures.sign(keys, RevocationAdminService.signingBytes(tokenId, at));
    }

    @Test
    void issuerOfParentCanRevokeAndDescendantsGoWithIt() {
        Instant at = Instant.now();
        List<String> revoked = admin.revoke(
                root.tokenId(), fx.userDid, at, sign(fx.userKeys, root.tokenId(), at));
        assertThat(revoked).containsExactly(root.tokenId(), child.tokenId());
        assertThat(fx.revocationService.isRevoked(child.tokenId())).isTrue();
    }

    @Test
    void delegatorCanRevokeOnlyWhatItIssued() {
        Instant at = Instant.now();
        String orchestratorDid = fx.didOf(orchestratorKeys);
        assertThat(admin.revoke(child.tokenId(), orchestratorDid, at,
                sign(orchestratorKeys, child.tokenId(), at))).containsExactly(child.tokenId());
        assertThat(fx.revocationService.isRevoked(root.tokenId())).isFalse();
        assertThatThrownBy(() -> admin.revoke(root.tokenId(), orchestratorDid, at,
                sign(orchestratorKeys, root.tokenId(), at))).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void rejectsStrangersWrongSignaturesStaleAndReplayedRequests() {
        KeyPair stranger = fx.newKeys();
        Instant at = Instant.now();
        assertThatThrownBy(() -> admin.revoke(root.tokenId(), fx.didOf(stranger), at,
                sign(stranger, root.tokenId(), at))).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> admin.revoke(root.tokenId(), fx.userDid, at,
                sign(stranger, root.tokenId(), at))).isInstanceOf(AccessDeniedException.class);
        Instant old = at.minusSeconds(600);
        assertThatThrownBy(() -> admin.revoke(root.tokenId(), fx.userDid, old,
                sign(fx.userKeys, root.tokenId(), old))).isInstanceOf(AccessDeniedException.class);

        String signature = sign(fx.userKeys, child.tokenId(), at);
        admin.revoke(child.tokenId(), fx.userDid, at, signature);
        assertThatThrownBy(() -> admin.revoke(child.tokenId(), fx.userDid, at, signature))
                .isInstanceOf(AccessDeniedException.class);
    }
}
