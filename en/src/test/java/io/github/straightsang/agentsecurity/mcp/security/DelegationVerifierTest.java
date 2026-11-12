package io.github.straightsang.agentsecurity.mcp.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.delegation.DelegationProperties;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationRevocationService;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationSignatureVerifier;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationTokenCanonicalizer;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationTokenService;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DelegationVerifierTest {
    private final Ed25519KeyService keyService = new Ed25519KeyService();
    private final DidKeyService didKeyService = new DidKeyService();
    private final DelegationTokenCanonicalizer canonicalizer = new DelegationTokenCanonicalizer();

    private KeyPair userKeys;
    private KeyPair delegatorKeys;
    private KeyPair finalAgentKeys;
    private String userDid;
    private String delegatorDid;
    private String finalAgentDid;
    private DelegationRevocationService revocationService;
    private DelegationVerifier verifier;
    private DelegationTokenService tokenService;

    @BeforeEach
    void setUp() {
        userKeys = keyService.generateKeyPair();
        delegatorKeys = keyService.generateKeyPair();
        finalAgentKeys = keyService.generateKeyPair();
        userDid = didKeyService.createDid(userKeys.getPublic());
        delegatorDid = didKeyService.createDid(delegatorKeys.getPublic());
        finalAgentDid = didKeyService.createDid(finalAgentKeys.getPublic());

        DelegationProperties properties = new DelegationProperties(
                "agent-security-mcp", 3, Set.of(userDid));
        revocationService = new DelegationRevocationService();
        DelegationSignatureVerifier signatureVerifier = new DelegationSignatureVerifier(
                didKeyService, canonicalizer, new CommandIntegrityVerifier());
        verifier = new DelegationVerifier(signatureVerifier, revocationService, properties);
        tokenService = new DelegationTokenService(canonicalizer, verifier);
    }

    @Test
    void acceptsValidAttenuatedChain() {
        DelegationToken parent = root(
                Set.of("calculator_add", "read_lab_document"),
                Set.of("calculator", "docs/readme.txt"),
                Instant.now().plusSeconds(600));
        DelegationToken child = tokenService.delegate(
                parent, finalAgentDid,
                Set.of("calculator_add"), Set.of("calculator"),
                Instant.now().plusSeconds(300), delegatorKeys.getPrivate());

        DelegationToken leaf = verifier.verifyChain(
                List.of(parent, child), finalAgentDid, "calculator_add", "calculator");

        assertThat(leaf.tokenId()).isEqualTo(child.tokenId());
        assertThat(leaf.actions()).containsExactly("calculator_add");
    }

    @Test
    void rejectsActionExpansion() {
        DelegationToken parent = root(
                Set.of("calculator_add"), Set.of("calculator"), Instant.now().plusSeconds(600));
        assertThatThrownBy(() -> tokenService.delegate(
                parent, finalAgentDid,
                Set.of("calculator_add", "read_lab_document"), Set.of("calculator"),
                Instant.now().plusSeconds(300), delegatorKeys.getPrivate()))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("부모에게 없는 action을 자식에게 위임할 수 없습니다.");
    }

    @Test
    void rejectsResourceExpansion() {
        DelegationToken parent = root(
                Set.of("read_lab_document"), Set.of("docs/readme.txt"), Instant.now().plusSeconds(600));
        assertThatThrownBy(() -> tokenService.delegate(
                parent, finalAgentDid,
                Set.of("read_lab_document"), Set.of("docs/readme.txt", "secrets/key.txt"),
                Instant.now().plusSeconds(300), delegatorKeys.getPrivate()))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("부모에게 없는 resource를 자식에게 위임할 수 없습니다.");
    }

    @Test
    void rejectsLongerChildExpiration() {
        Instant parentExpiry = Instant.now().plusSeconds(300);
        DelegationToken parent = root(
                Set.of("calculator_add"), Set.of("calculator"), parentExpiry);
        assertThatThrownBy(() -> tokenService.delegate(
                parent, finalAgentDid,
                Set.of("calculator_add"), Set.of("calculator"),
                parentExpiry.plusSeconds(1), delegatorKeys.getPrivate()))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("자식 토큰의 만료 시각은 부모보다 늦을 수 없습니다.");
    }

    @Test
    void rejectsTamperedAndRevokedTokens() {
        DelegationToken parent = root(
                Set.of("calculator_add"), Set.of("calculator"), Instant.now().plusSeconds(600));
        DelegationToken tampered = new DelegationToken(
                parent.tokenId(), parent.parentTokenId(), parent.issuer(), parent.subject(),
                parent.audience(), Set.of("calculator_add", "read_lab_document"), parent.resources(),
                parent.issuedAt(), parent.expiresAt(), parent.delegationDepth(), parent.signature());

        assertThatThrownBy(() -> verifier.verifyToken(tampered))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("위임 토큰의 issuer 서명이 올바르지 않습니다.");

        revocationService.revoke(parent.tokenId());
        assertThatThrownBy(() -> verifier.verifyToken(parent))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("폐기된 위임 토큰입니다.");
    }

    @Test
    void rejectsUntrustedRootIssuer() {
        KeyPair attackerKeys = keyService.generateKeyPair();
        String attackerDid = didKeyService.createDid(attackerKeys.getPublic());
        DelegationToken untrusted = tokenService.issueRoot(
                attackerDid, finalAgentDid, "agent-security-mcp",
                Set.of("calculator_add"), Set.of("calculator"),
                Instant.now().plusSeconds(300), attackerKeys.getPrivate());

        assertThatThrownBy(() -> verifier.verifyChain(
                List.of(untrusted), finalAgentDid, "calculator_add", "calculator"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("신뢰할 수 없는 최초 위임 발급자입니다.");
    }

    private DelegationToken root(
            Set<String> actions, Set<String> resources, Instant expiresAt) {
        return tokenService.issueRoot(
                userDid, delegatorDid, "agent-security-mcp",
                actions, resources, expiresAt, userKeys.getPrivate());
    }
}
