package io.github.straightsang.agentsecurity.mcp.opa;

import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import java.util.Set;

/* Gateway가 검증을 끝낸 최종 위임 사실만 OPA에 전달한다. */
public record DelegationContext(
        String rootIssuer,
        String subject,
        String audience,
        Set<String> actions,
        Set<String> resources,
        int delegationDepth,
        String tokenId) {

    public static DelegationContext from(String rootIssuer, DelegationToken leaf) {
        return new DelegationContext(
                rootIssuer, leaf.subject(), leaf.audience(), leaf.actions(), leaf.resources(),
                leaf.delegationDepth(), leaf.tokenId());
    }
}
