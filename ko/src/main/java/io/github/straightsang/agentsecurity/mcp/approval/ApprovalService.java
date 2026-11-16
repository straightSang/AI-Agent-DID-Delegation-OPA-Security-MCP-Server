package io.github.straightsang.agentsecurity.mcp.approval;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import io.github.straightsang.agentsecurity.mcp.state.InMemorySecurityStateStore;
import io.github.straightsang.agentsecurity.mcp.state.SecurityStateStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/*
 * 승인 토큰의 서명, 만료, 요청 결합, 신뢰할 승인자, 일회 사용을 검사한다.
 * 사용 완료 상태는 SecurityStateStore에 저장하므로 DynamoDB 구현을 쓰면 서버가 여러 대여도 일회 사용이 지켜진다.
 */
@Service
public class ApprovalService {
    private final ApprovalProperties properties;
    private final ApprovalTokenCanonicalizer canonicalizer;
    private final DidKeyService didKeyService;
    private final CommandIntegrityVerifier integrityVerifier;
    private static final String NAMESPACE = "approval";
    private final SecurityStateStore stateStore;
    private final Clock clock;

    /* 단위 테스트용: 메모리 상태 저장소를 쓴다. */
    public ApprovalService(
            ApprovalProperties properties,
            ApprovalTokenCanonicalizer canonicalizer,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier) {
        this(properties, canonicalizer, didKeyService, integrityVerifier,
                new InMemorySecurityStateStore(), Clock.systemUTC());
    }

    /* 운영용 생성자를 Spring이 선택하도록 명시한다. */
    @Autowired
    public ApprovalService(
            ApprovalProperties properties,
            ApprovalTokenCanonicalizer canonicalizer,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            SecurityStateStore stateStore) {
        this(properties, canonicalizer, didKeyService, integrityVerifier,
                stateStore, Clock.systemUTC());
    }

    /* 테스트 전용: 시계를 바꿀 수 있다. */
    ApprovalService(
            ApprovalProperties properties,
            ApprovalTokenCanonicalizer canonicalizer,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            Clock clock) {
        this(properties, canonicalizer, didKeyService, integrityVerifier,
                new InMemorySecurityStateStore(), clock);
    }

    ApprovalService(
            ApprovalProperties properties,
            ApprovalTokenCanonicalizer canonicalizer,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            SecurityStateStore stateStore,
            Clock clock) {
        this.properties = properties;
        this.canonicalizer = canonicalizer;
        this.didKeyService = didKeyService;
        this.integrityVerifier = integrityVerifier;
        this.stateStore = stateStore;
        this.clock = clock;
    }

    /* 승인자가 서명하기 전의 토큰 초안을 만든다. 서명할 바이트는 canonicalizer가 정한다. */
    public ApprovalToken draft(String requestHash, String actorDid, String target, String approverDid) {
        Instant issuedAt = Instant.now(clock);
        return new ApprovalToken(
                UUID.randomUUID().toString(), requestHash, actorDid, target, approverDid,
                issuedAt, issuedAt.plus(properties.tokenTtl()), null);
    }

    public byte[] signingBytes(ApprovalToken unsignedToken) {
        return canonicalizer.canonicalize(unsignedToken);
    }

    /* 로컬 테스트용 발급 메서드다. 운영 환경에서는 사용자 지갑/KMS가 서명한다. */
    public ApprovalToken issueForLab(
            String requestHash,
            String actorDid,
            String target,
            String approverDid,
            PrivateKey approverPrivateKey) {
        ApprovalToken unsigned = draft(requestHash, actorDid, target, approverDid);
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(approverPrivateKey);
            signer.update(canonicalizer.canonicalize(unsigned));
            return unsigned.withSignature(Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signer.sign()));
        } catch (Exception exception) {
            throw new IllegalStateException("승인 토큰 서명에 실패했습니다.", exception);
        }
    }

    /* 서명, 만료, 요청 결합, 승인자 신뢰, 미사용 여부를 검사하되 사용 처리는 하지 않는다. */
    public void verifyOnly(
            ApprovalToken token,
            String expectedRequestHash,
            String expectedActorDid,
            String expectedTarget) {
        if (token == null) deny("사용자 승인 토큰이 필요합니다.");
        if (!properties.isTrustedApprover(token.approverDid())) {
            deny("신뢰할 수 없는 승인자입니다.");
        }
        if (!token.requestHash().equals(expectedRequestHash)
                || !token.actorDid().equals(expectedActorDid)
                || !token.target().equals(expectedTarget)) {
            deny("승인된 요청과 실행하려는 요청이 일치하지 않습니다.");
        }
        if (!token.expiresAt().isAfter(Instant.now(clock))) {
            deny("사용자 승인 토큰이 만료되었습니다.");
        }
        if (stateStore.exists(NAMESPACE, token.approvalId(), Instant.now(clock))) {
            deny("이미 사용된 승인 토큰입니다.");
        }

        try {
            byte[] signature = Base64.getUrlDecoder().decode(token.signature());
            boolean valid = integrityVerifier.verify(
                    didKeyService.resolvePublicKey(token.approverDid()),
                    canonicalizer.canonicalize(token), signature);
            if (!valid) deny("사용자 승인 서명이 올바르지 않습니다.");
        } catch (AccessDeniedException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            deny("사용자 승인 토큰 형식이 올바르지 않습니다.");
        }

    }

    /* 검사를 통과한 토큰을 원자적으로 사용 처리한다. 동시에 두 번 쓰려 하면 한 번만 성공한다. */
    public void consume(ApprovalToken token) {
        boolean claimed = stateStore.putIfAbsent(
                NAMESPACE, token.approvalId(), "consumed",
                token.expiresAt().plus(Duration.ofHours(1)));
        if (!claimed) deny("이미 사용된 승인 토큰입니다.");
    }

    public void verifyAndConsume(
            ApprovalToken token,
            String expectedRequestHash,
            String expectedActorDid,
            String expectedTarget) {
        verifyOnly(token, expectedRequestHash, expectedActorDid, expectedTarget);
        consume(token);
    }

    private void deny(String message) {
        throw new AccessDeniedException(message);
    }
}
