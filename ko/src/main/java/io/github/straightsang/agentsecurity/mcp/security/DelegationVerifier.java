package io.github.straightsang.agentsecurity.mcp.security;

import io.github.straightsang.agentsecurity.mcp.delegation.DelegationProperties;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationRevocationService;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationSignatureVerifier;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/*
 * 위임 체인의 서명과 권한 축소를 검증한다.
 * 부모보다 action/resource/만료 범위가 넓어지면 자동으로 줄이지 않고 명시적으로 거부한다.
 */
@Component
public class DelegationVerifier {
    private static final Duration ALLOWED_CLOCK_SKEW = Duration.ofSeconds(30);

    private final DelegationSignatureVerifier signatureVerifier;
    private final DelegationRevocationService revocationService;
    private final DelegationProperties properties;
    private final Clock clock;

    /* 운영용 생성자를 Spring이 선택하도록 명시한다. Clock 생성자는 테스트 전용이다. */
    @Autowired
    public DelegationVerifier(
            DelegationSignatureVerifier signatureVerifier,
            DelegationRevocationService revocationService,
            DelegationProperties properties) {
        this(signatureVerifier, revocationService, properties, Clock.systemUTC());
    }

    DelegationVerifier(
            DelegationSignatureVerifier signatureVerifier,
            DelegationRevocationService revocationService,
            DelegationProperties properties,
            Clock clock) {
        this.signatureVerifier = signatureVerifier;
        this.revocationService = revocationService;
        this.properties = properties;
        this.clock = clock;
    }

    /* root부터 최종 Agent 토큰까지 순서대로 검증하고 최종 토큰을 반환한다. */
    public DelegationToken verifyChain(
            List<DelegationToken> chain,
            String authenticatedAgentDid,
            String requestedAction,
            String requestedResource) {
        if (chain == null || chain.isEmpty()) {
            deny("권한 위임 토큰 체인이 없습니다.");
        }
        if (chain.size() > properties.maxDepth() + 1) {
            deny("허용된 위임 체인 길이를 초과했습니다.");
        }

        DelegationToken root = chain.getFirst();
        verifyToken(root);
        if (root.delegationDepth() != 0 || root.parentTokenId() != null) {
            deny("최초 위임 토큰의 depth 또는 parentTokenId가 올바르지 않습니다.");
        }
        if (!properties.isTrustedIssuer(root.issuer())) {
            deny("신뢰할 수 없는 최초 위임 발급자입니다.");
        }

        for (int index = 1; index < chain.size(); index++) {
            DelegationToken parent = chain.get(index - 1);
            DelegationToken child = chain.get(index);
            verifyToken(child);
            verifyAttenuation(parent, child);
        }

        DelegationToken leaf = chain.getLast();
        if (!leaf.subject().equals(authenticatedAgentDid)) {
            deny("최종 위임 토큰의 subject가 인증된 Agent와 일치하지 않습니다.");
        }
        if (!leaf.audience().equals(properties.audience())) {
            deny("위임 토큰의 audience가 현재 MCP 서버와 일치하지 않습니다.");
        }
        if (!leaf.actions().contains(requestedAction)) {
            deny("위임받지 않은 행동입니다.");
        }
        if (!leaf.resources().contains(requestedResource)) {
            deny("요청한 리소스가 위임 범위에 포함되지 않습니다.");
        }
        return leaf;
    }

    /* 자식 토큰이 부모 토큰보다 권한이 좁거나 같은지 검사한다. */
    public void verifyAttenuation(DelegationToken parent, DelegationToken child) {
        if (!child.parentTokenId().equals(parent.tokenId())) {
            deny("자식 토큰이 올바른 부모 토큰을 참조하지 않습니다.");
        }
        if (!child.issuer().equals(parent.subject())) {
            deny("자식 토큰 issuer는 부모 토큰 subject와 같아야 합니다.");
        }
        if (!child.audience().equals(parent.audience())) {
            deny("위임 과정에서 audience를 변경할 수 없습니다.");
        }
        if (!parent.actions().containsAll(child.actions())) {
            deny("부모에게 없는 action을 자식에게 위임할 수 없습니다.");
        }
        if (!parent.resources().containsAll(child.resources())) {
            deny("부모에게 없는 resource를 자식에게 위임할 수 없습니다.");
        }
        if (child.expiresAt().isAfter(parent.expiresAt())) {
            deny("자식 토큰의 만료 시각은 부모보다 늦을 수 없습니다.");
        }
        if (child.issuedAt().isBefore(parent.issuedAt())) {
            deny("자식 토큰 발급 시각은 부모보다 앞설 수 없습니다.");
        }
        if (child.delegationDepth() != parent.delegationDepth() + 1) {
            deny("자식 delegationDepth는 부모보다 정확히 1 커야 합니다.");
        }
        if (child.delegationDepth() > properties.maxDepth()) {
            deny("최대 위임 깊이를 초과했습니다.");
        }
    }

    /* 토큰 하나의 필수 값, 시간, 폐기 상태, issuer 서명을 검사한다. */
    public void verifyToken(DelegationToken token) {
        if (token == null) deny("권한 위임 토큰이 없습니다.");
        validateRequiredFields(token);

        Instant now = Instant.now(clock);
        if (token.issuedAt().isAfter(now.plus(ALLOWED_CLOCK_SKEW))) {
            deny("위임 토큰의 issuedAt이 미래 시각입니다.");
        }
        if (!token.expiresAt().isAfter(now)) {
            deny("권한 위임 토큰이 만료되었습니다.");
        }
        if (!token.expiresAt().isAfter(token.issuedAt())) {
            deny("위임 토큰의 만료 시각이 발급 시각보다 늦어야 합니다.");
        }
        if (token.delegationDepth() < 0 || token.delegationDepth() > properties.maxDepth()) {
            deny("위임 깊이가 허용 범위를 벗어났습니다.");
        }
        if (revocationService.isRevoked(token.tokenId())) {
            deny("폐기된 위임 토큰입니다.");
        }
        signatureVerifier.verify(token);
    }

    private void validateRequiredFields(DelegationToken token) {
        if (isBlank(token.tokenId()) || isBlank(token.issuer()) || isBlank(token.subject())
                || isBlank(token.audience()) || isBlank(token.signature())
                || token.issuedAt() == null || token.expiresAt() == null
                || invalidSet(token.actions()) || invalidSet(token.resources())) {
            deny("위임 토큰의 필수 항목이 누락되었습니다.");
        }
        if (token.delegationDepth() > 0 && isBlank(token.parentTokenId())) {
            deny("재위임 토큰에는 parentTokenId가 필요합니다.");
        }
    }

    private boolean invalidSet(Set<String> values) {
        return values == null || values.isEmpty()
                || values.stream().anyMatch(this::isBlank);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private void deny(String message) {
        throw new AccessDeniedException(message);
    }
}
