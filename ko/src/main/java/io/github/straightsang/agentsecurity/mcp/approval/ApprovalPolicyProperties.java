package io.github.straightsang.agentsecurity.mcp.approval;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/*
 * 승인 정책 설정.
 * highRequiredApprovals: HIGH 위험 요청에 필요한 서로 다른 승인자 수 (기본 1, 2 이상이면 M-of-N)
 * channelEnabled: 사전 승인 채널(한도형 승인) 사용 여부
 * channelMaxUses / channelMaxTtl: 채널 한 개로 승인할 수 있는 최대 횟수와 최대 유효시간
 */
@ConfigurationProperties(prefix = "security.approval-policy")
public record ApprovalPolicyProperties(
        Integer highRequiredApprovals,
        Boolean channelEnabled,
        Integer channelMaxUses,
        Duration channelMaxTtl) {
    public ApprovalPolicyProperties {
        highRequiredApprovals = highRequiredApprovals == null || highRequiredApprovals < 1
                ? 1 : highRequiredApprovals;
        channelEnabled = channelEnabled == null ? Boolean.TRUE : channelEnabled;
        channelMaxUses = channelMaxUses == null || channelMaxUses < 1 ? 10 : channelMaxUses;
        channelMaxTtl = channelMaxTtl == null ? Duration.ofHours(1) : channelMaxTtl;
    }

    public static ApprovalPolicyProperties defaults() {
        return new ApprovalPolicyProperties(null, null, null, null);
    }
}
