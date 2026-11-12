package io.github.straightsang.agentsecurity.mcp.approval;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/* 승인 토큰의 서명, 만료, 요청 결합, 신뢰할 승인자, 일회 사용을 검사한다. */
@Service
public class ApprovalService {
    private final ApprovalProperties properties;
    private final ApprovalTokenCanonicalizer canonicalizer;
    private final DidKeyService didKeyService;
    private final CommandIntegrityVerifier integrityVerifier;
    private final Set<String> consumedApprovalIds = ConcurrentHashMap.newKeySet();
    private final Clock clock;

    /* 운영용 생성자를 Spring이 선택하도록 명시한다. 아래 Clock 생성자는 테스트에서만 사용한다. */
    @Autowired
    public ApprovalService(
            ApprovalProperties properties,
            ApprovalTokenCanonicalizer canonicalizer,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier) {
        this(properties, canonicalizer, didKeyService, integrityVerifier, Clock.systemUTC());
    }

    ApprovalService(
            ApprovalProperties properties,
            ApprovalTokenCanonicalizer canonicalizer,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            Clock clock) {
        this.properties = properties;
        this.canonicalizer = canonicalizer;
        this.didKeyService = didKeyService;
        this.integrityVerifier = integrityVerifier;
        this.clock = clock;
    }

    /* 로컬 테스트용 발급 메서드다. 운영 환경에서는 사용자 지갑/KMS가 서명한다. */
    public ApprovalToken issueForLab(
            String requestHash,
            String actorDid,
            String target,
            String approverDid,
            PrivateKey approverPrivateKey) {
        Instant issuedAt = Instant.now(clock);
        ApprovalToken unsigned = new ApprovalToken(
                UUID.randomUUID().toString(), requestHash, actorDid, target, approverDid,
                issuedAt, issuedAt.plus(properties.tokenTtl()), null);
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

    public void verifyAndConsume(
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
        if (consumedApprovalIds.contains(token.approvalId())) {
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

        if (!consumedApprovalIds.add(token.approvalId())) {
            deny("이미 사용된 승인 토큰입니다.");
        }
    }

    private void deny(String message) {
        throw new AccessDeniedException(message);
    }
}
