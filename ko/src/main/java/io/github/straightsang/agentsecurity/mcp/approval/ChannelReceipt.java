package io.github.straightsang.agentsecurity.mcp.approval;

/* 채널을 한 번 사용했다는 Gateway 서명 영수증이다. sequence는 이 채널의 몇 번째 사용인지 나타낸다. */
public record ChannelReceipt(
        String channelId,
        int sequence,
        int maxUses,
        String requestHash,
        String gatewayDid,
        String gatewaySignature) {

    public String note() {
        return "channel:" + channelId + "#" + sequence + "/" + maxUses;
    }
}
