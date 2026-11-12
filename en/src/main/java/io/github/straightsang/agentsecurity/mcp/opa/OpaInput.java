package io.github.straightsang.agentsecurity.mcp.opa;

import java.util.Map;

/* Derives authenticated and delegationValid only from Gateway verification, never from caller claims. */
public record OpaInput(
        String actor,
        boolean authenticated,
        boolean delegationValid,
        String action,
        String resource,
        Map<String, Object> arguments,
        DelegationContext delegation) {
}
