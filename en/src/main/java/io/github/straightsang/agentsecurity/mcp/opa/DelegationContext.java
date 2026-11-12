package io.github.straightsang.agentsecurity.mcp.opa;

import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import java.util.Set;

/* Passes only Gateway-verified delegation facts to OPA. */
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
