package io.github.straightsang.agentsecurity.mcp.approval;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.testsupport.Fixtures;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MultiApprovalAndChannelTest {
    private Fixtures fx;
    private KeyPair keysA;
    private KeyPair keysB;
    private String didA;
    private String didB;
    private ApprovalProperties approvalProperties;
    private ApprovalService approvalService;
    private MultiApprovalService multi;
    private ApprovalChannelService channels;

    @BeforeEach
    void setUp() {
        fx = new Fixtures();
        keysA = fx.newKeys();
        keysB = fx.newKeys();
        didA = fx.didOf(keysA);
        didB = fx.didOf(keysB);
        approvalProperties = new ApprovalProperties(Duration.ofMinutes(2), Set.of(didA, didB));
        approvalService = new ApprovalService(
                approvalProperties, new ApprovalTokenCanonicalizer(), fx.didKeyService,
                fx.integrityVerifier, fx.stateStore);
        ApprovalPolicyProperties policy = new ApprovalPolicyProperties(2, true, 3, Duration.ofHours(1));
        multi = new MultiApprovalService(approvalService, approvalProperties, policy);
        channels = new ApprovalChannelService(
                approvalProperties, policy, fx.didKeyService, fx.integrityVerifier,
                fx.stateStore, fx.gatewayKeys);
    }

    private ApprovalToken token(KeyPair keys, String did, String hash) {
        return approvalService.issueForLab(hash, "did:key:agent", "target", did, keys.getPrivate());
    }

    @Test
    void requiresTwoDistinctApproversAndConsumesNothingOnFailure() {
        ApprovalToken a = token(keysA, didA, "h");
        ApprovalToken a2 = token(keysA, didA, "h");
        ApprovalToken b = token(keysB, didB, "h");

        assertThatThrownBy(() -> multi.verifyAndConsumeAll(List.of(a), 2, "h", "did:key:agent", "target"))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> multi.verifyAndConsumeAll(List.of(a, a2), 2, "h", "did:key:agent", "target"))
                .isInstanceOf(AccessDeniedException.class);
        // 위의 실패 때문에 a가 소모되지 않았어야 한다
        assertThatCode(() -> multi.verifyAndConsumeAll(List.of(a, b), 2, "h", "did:key:agent", "target"))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> multi.verifyAndConsumeAll(List.of(a, b), 2, "h", "did:key:agent", "target"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void oneBadTokenAmongTwoConsumesNeither() {
        ApprovalToken a = token(keysA, didA, "h");
        ApprovalToken wrongHash = token(keysB, didB, "other");
        assertThatThrownBy(() -> multi.verifyAndConsumeAll(
                List.of(a, wrongHash), 2, "h", "did:key:agent", "target"))
                .isInstanceOf(AccessDeniedException.class);
        assertThatCode(() -> approvalService.verifyAndConsume(a, "h", "did:key:agent", "target"))
                .doesNotThrowAnyException();
    }

    @Test
    void agentCannotApproveItsOwnRequest() {
        ApprovalToken self = approvalService.issueForLab(
                "h", didA, "target", didA, keysA.getPrivate());
        ApprovalToken b = approvalService.issueForLab(
                "h", didA, "target", didB, keysB.getPrivate());
        assertThatThrownBy(() -> multi.verifyAndConsumeAll(List.of(self, b), 2, "h", didA, "target"))
                .isInstanceOf(AccessDeniedException.class);
    }

    private ApprovalChannelGrant grant(KeyPair approverKeys, String approverDid, int maxUses, long ttl) {
        Instant now = Instant.now();
        ApprovalChannelGrant draft = new ApprovalChannelGrant(
                "channel-" + Math.abs(approverDid.hashCode()) + "-" + now.toEpochMilli(),
                approverDid, "did:key:agent", Set.of("calculator_add"), Set.of("calculator"),
                maxUses, now, now.plusSeconds(ttl), null);
        String signature = Fixtures.sign(approverKeys, channels.signingBytes(draft));
        return new ApprovalChannelGrant(
                draft.channelId(), draft.approverDid(), draft.actorDid(), draft.allowedActions(),
                draft.allowedTargets(), draft.maxUses(), draft.openedAt(), draft.expiresAt(), signature);
    }

    @Test
    void channelAllowsLimitedUsesAndReturnsSignedReceipts() {
        ApprovalChannelGrant grant = grant(keysA, didA, 2, 600);
        ChannelReceipt first = channels.useOne(grant, "did:key:agent", "calculator_add", "calculator", "h1");
        ChannelReceipt second = channels.useOne(grant, "did:key:agent", "calculator_add", "calculator", "h2");
        assertThat(first.sequence()).isEqualTo(1);
        assertThat(second.sequence()).isEqualTo(2);
        assertThatThrownBy(() -> channels.useOne(grant, "did:key:agent", "calculator_add", "calculator", "h3"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void channelRejectsWrongActorActionTargetTamperingAndAbusiveSettings() {
        ApprovalChannelGrant grant = grant(keysA, didA, 2, 600);
        assertThatThrownBy(() -> channels.useOne(grant, "did:key:other", "calculator_add", "calculator", "h"))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> channels.useOne(grant, "did:key:agent", "read_lab_document", "calculator", "h"))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> channels.useOne(grant, "did:key:agent", "calculator_add", "docs/x", "h"))
                .isInstanceOf(AccessDeniedException.class);

        ApprovalChannelGrant widened = new ApprovalChannelGrant(
                grant.channelId(), grant.approverDid(), grant.actorDid(), grant.allowedActions(),
                Set.of("calculator", "personal/data"), grant.maxUses(), grant.openedAt(),
                grant.expiresAt(), grant.signature());
        assertThatThrownBy(() -> channels.useOne(widened, "did:key:agent", "calculator_add", "personal/data", "h"))
                .isInstanceOf(AccessDeniedException.class);

        assertThatThrownBy(() -> channels.useOne(
                grant(keysA, didA, 99, 600), "did:key:agent", "calculator_add", "calculator", "h"))
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> channels.useOne(
                grant(keysA, didA, 2, 3 * 3600), "did:key:agent", "calculator_add", "calculator", "h"))
                .isInstanceOf(AccessDeniedException.class);

        KeyPair untrusted = fx.newKeys();
        assertThatThrownBy(() -> channels.useOne(
                grant(untrusted, fx.didOf(untrusted), 2, 600), "did:key:agent", "calculator_add", "calculator", "h"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void concurrentUsesNeverExceedTheLimit() throws Exception {
        ApprovalChannelGrant grant = grant(keysA, didA, 3, 600);
        int attempts = 12;
        java.util.concurrent.atomic.AtomicInteger success = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(6);
        java.util.List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
        for (int index = 0; index < attempts; index++) {
            final int n = index;
            futures.add(pool.submit(() -> {
                try {
                    channels.useOne(grant, "did:key:agent", "calculator_add", "calculator", "h" + n);
                    success.incrementAndGet();
                } catch (AccessDeniedException ignored) {
                    // 한도 초과는 정상 거부다
                }
            }));
        }
        for (var future : futures) future.get();
        pool.shutdown();
        assertThat(success.get()).isEqualTo(3);
    }

    @Test
    void requestHashV2ChangesWhenChainOrAudienceChanges() {
        var hashes = new io.github.straightsang.agentsecurity.mcp.security.CanonicalRequestHashService();
        var args = java.util.Map.<String, Object>of("a", 1, "b", 2);
        String base = hashes.hashRequest("did", "act", "res", args, "r1", "res", List.of("t1", "t2"), "aud");
        assertThat(hashes.hashRequest("did", "act", "res", args, "r1", "res", List.of("t1", "t2"), "aud"))
                .isEqualTo(base);
        assertThat(hashes.hashRequest("did", "act", "res", args, "r1", "res", List.of("t1", "t3"), "aud"))
                .isNotEqualTo(base);
        assertThat(hashes.hashRequest("did", "act", "res", args, "r1", "res", List.of("t2", "t1"), "aud"))
                .isNotEqualTo(base);
        assertThat(hashes.hashRequest("did", "act", "res", args, "r1", "res", List.of("t1", "t2"), "other"))
                .isNotEqualTo(base);
        assertThat(hashes.hashRequest("did", "act", "res", args, "r1", "res"))
                .isNotEqualTo(hashes.hashRequest("did", "act", "res", args, "r1", "res", List.of(), ""));
    }
}
