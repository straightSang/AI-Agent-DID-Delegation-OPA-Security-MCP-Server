package io.github.straightsang.agentsecurity.mcp.approval;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ApprovalServiceTest {
    private final Ed25519KeyService keyService = new Ed25519KeyService();
    private final DidKeyService didKeyService = new DidKeyService();
    private KeyPair approverKeys;
    private String approverDid;
    private ApprovalService service;

    @BeforeEach
    void setUp() {
        approverKeys = keyService.generateKeyPair();
        approverDid = didKeyService.createDid(approverKeys.getPublic());
        service = new ApprovalService(
                new ApprovalProperties(Duration.ofMinutes(2), Set.of(approverDid)),
                new ApprovalTokenCanonicalizer(), didKeyService, new CommandIntegrityVerifier());
    }

    @Test
    void acceptsMatchingApprovalOnce() {
        ApprovalToken token = service.issueForLab(
                "hash-1", "did:key:agent", "external", approverDid, approverKeys.getPrivate());
        assertThatCode(() -> service.verifyAndConsume(
                token, "hash-1", "did:key:agent", "external"))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> service.verifyAndConsume(
                token, "hash-1", "did:key:agent", "external"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("이미 사용된 승인 토큰입니다.");
    }

    @Test
    void rejectsRequestChangedAfterApproval() {
        ApprovalToken token = service.issueForLab(
                "original-hash", "did:key:agent", "external", approverDid, approverKeys.getPrivate());
        assertThatThrownBy(() -> service.verifyAndConsume(
                token, "changed-hash", "did:key:agent", "external"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("승인된 요청과 실행하려는 요청이 일치하지 않습니다.");
    }
}
