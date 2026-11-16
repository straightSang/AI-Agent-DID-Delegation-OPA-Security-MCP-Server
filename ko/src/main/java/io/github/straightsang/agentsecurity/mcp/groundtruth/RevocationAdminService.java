package io.github.straightsang.agentsecurity.mcp.groundtruth;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import io.github.straightsang.agentsecurity.mcp.state.SecurityStateStore;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/*
 * 위임 토큰 폐기 요청을 인증하고 실행한다.
 * 요청자는 대상 토큰의 발급자이거나 그 조상 토큰의 발급자여야 한다(자기가 준 권한만 회수할 수 있다).
 * 요청 서명은 "REVOKE-V1\n{tokenId}\n{requestedAt}" 을 요청자 개인키로 서명한 값이며,
 * 60초 안의 요청만 받고 같은 서명은 한 번만 받는다(재전송 방지).
 */
@Service
public class RevocationAdminService {
    private static final String NAMESPACE = "revocation-admin";
    private static final Duration MAX_AGE = Duration.ofSeconds(60);

    private final PermissionGraphService graphService;
    private final DidKeyService didKeyService;
    private final CommandIntegrityVerifier integrityVerifier;
    private final SecurityStateStore stateStore;
    private final Clock clock;

    @Autowired
    public RevocationAdminService(
            PermissionGraphService graphService,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            SecurityStateStore stateStore) {
        this(graphService, didKeyService, integrityVerifier, stateStore, Clock.systemUTC());
    }

    RevocationAdminService(
            PermissionGraphService graphService,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            SecurityStateStore stateStore,
            Clock clock) {
        this.graphService = graphService;
        this.didKeyService = didKeyService;
        this.integrityVerifier = integrityVerifier;
        this.stateStore = stateStore;
        this.clock = clock;
    }

    public static byte[] signingBytes(String tokenId, Instant requestedAt) {
        return ("REVOKE-V1\n" + tokenId + "\n" + requestedAt).getBytes(StandardCharsets.UTF_8);
    }

    public List<String> revoke(String tokenId, String requesterDid, Instant requestedAt, String signature) {
        if (isBlank(tokenId) || isBlank(requesterDid) || requestedAt == null || isBlank(signature)) {
            throw new AccessDeniedException("폐기 요청의 필수 항목이 누락되었습니다.");
        }
        Instant now = Instant.now(clock);
        if (requestedAt.isBefore(now.minus(MAX_AGE)) || requestedAt.isAfter(now.plus(MAX_AGE))) {
            throw new AccessDeniedException("폐기 요청 시각이 허용 범위를 벗어났습니다.");
        }
        boolean valid;
        try {
            valid = integrityVerifier.verify(
                    didKeyService.resolvePublicKey(requesterDid),
                    signingBytes(tokenId, requestedAt),
                    Base64.getUrlDecoder().decode(signature));
        } catch (RuntimeException exception) {
            throw new AccessDeniedException("폐기 요청 서명 형식이 올바르지 않습니다.");
        }
        if (!valid) throw new AccessDeniedException("폐기 요청 서명이 올바르지 않습니다.");
        if (!mayRevoke(tokenId, requesterDid)) {
            throw new AccessDeniedException("이 토큰 또는 상위 토큰의 발급자만 폐기할 수 있습니다.");
        }
        boolean fresh = stateStore.putIfAbsent(NAMESPACE, signature, "used", now.plus(MAX_AGE.multipliedBy(2)));
        if (!fresh) throw new AccessDeniedException("이미 처리한 폐기 요청입니다.");
        return graphService.revokeCascade(tokenId, "revoke-" + now.toEpochMilli(),
                "revoked-by:" + requesterDid);
    }

    private boolean mayRevoke(String tokenId, String requesterDid) {
        PermissionGraph.TokenNode node = graphService.token(tokenId);
        int guard = 0;
        while (node != null && guard++ < 64) {
            if (node.issuer().equals(requesterDid)) return true;
            node = node.parentTokenId() == null ? null : graphService.token(node.parentTokenId());
        }
        return false;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
