package io.github.straightsang.agentsecurity.mcp.approval;

import io.github.straightsang.agentsecurity.mcp.audit.GatewaySigningKeyProvider;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import io.github.straightsang.agentsecurity.mcp.state.SecurityStateStore;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/*
 * 상태 채널 방식의 한도형 승인.
 *
 * 원리(Lightning 상태 채널에서 가져온 부분만)
 *  - 열기: 승인자가 한도와 범위를 서명한다. 서명된 문서가 곧 채널이며, 서버에 따로 저장하지 않는다.
 *  - 갱신: 사용할 때마다 순번(1, 2, ...)을 SecurityStateStore에 putIfAbsent로 선점한다. 선점은 원자적이고 되돌릴 수 없다.
 *  - 정산: 한도를 넘으면 더 이상 쓸 수 없고, 영수증은 Gateway가 서명해 감사 원장에 남긴다.
 * 결제, 라우팅(HTLC)은 승인 용도에 필요 없어 쓰지 않는다. 승인 경로에는 블록체인 합의를 넣지 않는다.
 *
 * 안전장치: HIGH 위험에만 쓸 수 있고, 행동과 대상 목록이 비어 있으면 거부하며, 최대 횟수와 유효시간에 상한이 있다.
 */
@Service
public class ApprovalChannelService {
    private static final String USE_NAMESPACE = "channel-use";
    private static final Duration ALLOWED_CLOCK_SKEW = Duration.ofSeconds(30);

    private final ApprovalProperties approvalProperties;
    private final ApprovalPolicyProperties policy;
    private final DidKeyService didKeyService;
    private final CommandIntegrityVerifier integrityVerifier;
    private final SecurityStateStore stateStore;
    private final GatewaySigningKeyProvider keyProvider;
    private final Clock clock;

    @Autowired
    public ApprovalChannelService(
            ApprovalProperties approvalProperties,
            ApprovalPolicyProperties policy,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            SecurityStateStore stateStore,
            GatewaySigningKeyProvider keyProvider) {
        this(approvalProperties, policy, didKeyService, integrityVerifier, stateStore,
                keyProvider, Clock.systemUTC());
    }

    ApprovalChannelService(
            ApprovalProperties approvalProperties,
            ApprovalPolicyProperties policy,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            SecurityStateStore stateStore,
            GatewaySigningKeyProvider keyProvider,
            Clock clock) {
        this.approvalProperties = approvalProperties;
        this.policy = policy;
        this.didKeyService = didKeyService;
        this.integrityVerifier = integrityVerifier;
        this.stateStore = stateStore;
        this.keyProvider = keyProvider;
        this.clock = clock;
    }

    /* 승인자가 채널 문서에 서명할 때 쓰는 정규화 바이트다. */
    public byte[] signingBytes(ApprovalChannelGrant grant) {
        return String.join("\n",
                "CHANNEL-V1", grant.channelId(), grant.approverDid(), grant.actorDid(),
                encodeSet(grant.allowedActions()), encodeSet(grant.allowedTargets()),
                Integer.toString(grant.maxUses()), grant.openedAt().toString(),
                grant.expiresAt().toString()).getBytes(StandardCharsets.UTF_8);
    }

    /* 채널을 한 번 사용한다. 조건을 하나라도 어기면 거부하고, 통과하면 순번을 선점해 영수증을 돌려준다. */
    public ChannelReceipt useOne(
            ApprovalChannelGrant grant,
            String actorDid,
            String action,
            String target,
            String requestHash) {
        if (!policy.channelEnabled()) deny("승인 채널 기능이 꺼져 있습니다.");
        validate(grant, actorDid, action, target);

        String counterPrefix = hashHex(signingBytes(grant));
        for (int sequence = 1; sequence <= grant.maxUses(); sequence++) {
            boolean claimed = stateStore.putIfAbsent(
                    USE_NAMESPACE, counterPrefix + "#" + sequence, requestHash,
                    grant.expiresAt().plus(Duration.ofHours(1)));
            if (claimed) {
                return receipt(grant, sequence, requestHash, actorDid, action, target);
            }
        }
        throw new AccessDeniedException("승인 채널의 사용 한도를 모두 소진했습니다.");
    }

    private void validate(ApprovalChannelGrant grant, String actorDid, String action, String target) {
        if (grant == null) deny("승인 채널이 없습니다.");
        if (isBlank(grant.channelId()) || isBlank(grant.approverDid()) || isBlank(grant.actorDid())
                || grant.openedAt() == null || grant.expiresAt() == null
                || isBlank(grant.signature())) {
            deny("승인 채널의 필수 항목이 누락되었습니다.");
        }
        if (grant.allowedActions() == null || grant.allowedActions().isEmpty()
                || grant.allowedTargets() == null || grant.allowedTargets().isEmpty()) {
            deny("승인 채널은 허용 행동과 허용 대상을 모두 지정해야 합니다.");
        }
        if (!approvalProperties.isTrustedApprover(grant.approverDid())) {
            deny("신뢰할 수 없는 승인자의 채널입니다.");
        }
        Instant now = Instant.now(clock);
        if (!grant.expiresAt().isAfter(now)) deny("승인 채널이 만료되었습니다.");
        if (grant.openedAt().isAfter(now.plus(ALLOWED_CLOCK_SKEW))) deny("승인 채널의 openedAt이 미래 시각입니다.");
        if (!grant.expiresAt().isAfter(grant.openedAt())
                || Duration.between(grant.openedAt(), grant.expiresAt()).compareTo(policy.channelMaxTtl()) > 0) {
            deny("승인 채널의 유효시간이 허용 범위를 벗어났습니다.");
        }
        if (grant.maxUses() < 1 || grant.maxUses() > policy.channelMaxUses()) {
            deny("승인 채널의 최대 사용 횟수가 허용 범위를 벗어났습니다.");
        }
        try {
            boolean valid = integrityVerifier.verify(
                    didKeyService.resolvePublicKey(grant.approverDid()), signingBytes(grant),
                    Base64.getUrlDecoder().decode(grant.signature()));
            if (!valid) deny("승인 채널 서명이 올바르지 않습니다.");
        } catch (AccessDeniedException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            deny("승인 채널 서명 형식이 올바르지 않습니다.");
        }
        if (!grant.actorDid().equals(actorDid)) deny("다른 Agent에게 발급된 승인 채널입니다.");
        if (grant.approverDid().equals(actorDid)) deny("요청한 Agent는 자기 채널의 승인자가 될 수 없습니다.");
        if (!grant.allowedActions().contains(action)) deny("승인 채널이 허용하지 않은 행동입니다.");
        if (!grant.allowedTargets().contains(target)) deny("승인 채널이 허용하지 않은 대상입니다.");
    }

    private ChannelReceipt receipt(
            ApprovalChannelGrant grant, int sequence, String requestHash,
            String actorDid, String action, String target) {
        byte[] message = String.join("\n",
                "CHANNEL-USE-V1", grant.channelId(), Integer.toString(sequence),
                Integer.toString(grant.maxUses()), requestHash, actorDid, action, target)
                .getBytes(StandardCharsets.UTF_8);
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyProvider.keyPair().getPrivate());
            signer.update(message);
            return new ChannelReceipt(
                    grant.channelId(), sequence, grant.maxUses(), requestHash,
                    keyProvider.gatewayDid(),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign()));
        } catch (Exception exception) {
            throw new IllegalStateException("승인 채널 영수증 서명에 실패했습니다.", exception);
        }
    }

    private String encodeSet(Set<String> values) {
        if (values == null) return "";
        List<String> encoded = new TreeSet<>(values).stream()
                .map(value -> URLEncoder.encode(value, StandardCharsets.UTF_8)).toList();
        return String.join(",", encoded);
    }

    private String hashHex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256을 사용할 수 없습니다.", exception);
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private void deny(String message) {
        throw new AccessDeniedException(message);
    }
}
