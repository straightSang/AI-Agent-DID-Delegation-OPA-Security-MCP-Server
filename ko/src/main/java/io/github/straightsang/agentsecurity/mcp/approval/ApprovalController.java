package io.github.straightsang.agentsecurity.mcp.approval;

import io.github.straightsang.agentsecurity.mcp.delegation.DelegationProperties;
import io.github.straightsang.agentsecurity.mcp.security.CanonicalRequestHashService;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/*
 * 승인 UI가 쓰는 준비 API다. 이 API는 서명하지 않는다. 서명은 승인자의 브라우저(WebCrypto)나 지갑이 한다.
 *
 *  POST /approval/prepare        요청 해시(위임 체인 포함)와 위험 설명을 돌려준다.
 *  POST /approval/draft          승인 토큰 초안과 "서명할 바이트"(base64url)를 돌려준다.
 *  POST /approval/channel/draft  한도형 승인 채널 초안과 서명할 바이트를 돌려준다.
 */
@RestController
@RequestMapping("/approval")
public class ApprovalController {
    private final RiskClassifier riskClassifier;
    private final CanonicalRequestHashService requestHashService;
    private final ApprovalService approvalService;
    private final ApprovalChannelService channelService;
    private final DelegationProperties delegationProperties;

    public ApprovalController(
            RiskClassifier riskClassifier,
            CanonicalRequestHashService requestHashService,
            ApprovalService approvalService,
            ApprovalChannelService channelService,
            DelegationProperties delegationProperties) {
        this.riskClassifier = riskClassifier;
        this.requestHashService = requestHashService;
        this.approvalService = approvalService;
        this.channelService = channelService;
        this.delegationProperties = delegationProperties;
    }

    @PostMapping("/prepare")
    public ResponseEntity<ApprovalPreparation> prepare(@RequestBody ApprovalRequest request) {
        if (request.delegationTokenIds() == null || request.delegationTokenIds().isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        String audience = request.audience() == null || request.audience().isBlank()
                ? delegationProperties.audience() : request.audience();
        String requestHash = requestHashService.hashRequest(
                request.actorDid(), request.action(), request.resource(), request.arguments(),
                request.requestId(), request.target(), request.delegationTokenIds(), audience);
        RiskAssessment assessment = riskClassifier.assess(
                request.action(), request.resource(), request.arguments(), request.target());
        return ResponseEntity.ok(new ApprovalPreparation(requestHash, assessment));
    }

    @PostMapping("/draft")
    public ResponseEntity<TokenDraft> draft(@RequestBody DraftRequest request) {
        if (isBlank(request.requestHash()) || isBlank(request.actorDid())
                || isBlank(request.target()) || isBlank(request.approverDid())) {
            return ResponseEntity.badRequest().build();
        }
        ApprovalToken draft = approvalService.draft(
                request.requestHash(), request.actorDid(), request.target(), request.approverDid());
        return ResponseEntity.ok(new TokenDraft(draft, encode(approvalService.signingBytes(draft))));
    }

    @PostMapping("/channel/draft")
    public ResponseEntity<ChannelDraft> channelDraft(@RequestBody ChannelDraftRequest request) {
        if (isBlank(request.approverDid()) || isBlank(request.actorDid())
                || request.allowedActions() == null || request.allowedTargets() == null
                || request.maxUses() < 1 || request.ttlSeconds() < 1) {
            return ResponseEntity.badRequest().build();
        }
        Instant openedAt = Instant.now();
        ApprovalChannelGrant draft = new ApprovalChannelGrant(
                UUID.randomUUID().toString(), request.approverDid(), request.actorDid(),
                Set.copyOf(request.allowedActions()), Set.copyOf(request.allowedTargets()),
                request.maxUses(), openedAt, openedAt.plusSeconds(request.ttlSeconds()), null);
        return ResponseEntity.ok(new ChannelDraft(draft, encode(channelService.signingBytes(draft))));
    }

    private String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record ApprovalRequest(
            String actorDid,
            String action,
            String resource,
            Map<String, Object> arguments,
            String requestId,
            String target,
            List<String> delegationTokenIds,
            String audience) {
    }

    public record ApprovalPreparation(String requestHash, RiskAssessment assessment) {
    }

    public record DraftRequest(String requestHash, String actorDid, String target, String approverDid) {
    }

    public record TokenDraft(ApprovalToken token, String signingBytes) {
    }

    public record ChannelDraftRequest(
            String approverDid, String actorDid, List<String> allowedActions,
            List<String> allowedTargets, int maxUses, long ttlSeconds) {
    }

    public record ChannelDraft(ApprovalChannelGrant grant, String signingBytes) {
    }
}
