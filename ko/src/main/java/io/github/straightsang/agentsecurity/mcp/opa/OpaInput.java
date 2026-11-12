package io.github.straightsang.agentsecurity.mcp.opa;

import java.util.Map;

/* authenticated/delegationValid는 요청자가 아니라 Gateway 검증 결과로만 만든다. */
public record OpaInput(
        String actor,
        boolean authenticated,
        boolean delegationValid,
        String action,
        String resource,
        Map<String, Object> arguments,
        DelegationContext delegation) {
}
