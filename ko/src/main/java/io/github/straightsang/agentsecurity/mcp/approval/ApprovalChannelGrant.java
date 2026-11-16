package io.github.straightsang.agentsecurity.mcp.approval;

import java.time.Instant;
import java.util.Set;

/*
 * 승인자가 서명해 둔 한도형 사전 승인(상태 채널의 "열기" 상태)이다.
 * 특정 Agent가, 허용된 행동과 허용된 대상에 한해, 만료 전까지 최대 maxUses번 승인 없이 실행할 수 있다.
 * 한 번 쓸 때마다 Gateway가 순번을 선점해 한도를 줄이고, 이미 쓴 순번은 되돌릴 수 없다.
 */
public record ApprovalChannelGrant(
        String channelId,
        String approverDid,
        String actorDid,
        Set<String> allowedActions,
        Set<String> allowedTargets,
        int maxUses,
        Instant openedAt,
        Instant expiresAt,
        String signature) {
}
