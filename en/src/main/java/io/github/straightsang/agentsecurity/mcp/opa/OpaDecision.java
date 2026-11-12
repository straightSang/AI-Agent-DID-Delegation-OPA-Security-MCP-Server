package io.github.straightsang.agentsecurity.mcp.opa;

import io.github.straightsang.agentsecurity.mcp.approval.PolicyOutcome;
import java.util.List;

public record OpaDecision(PolicyOutcome outcome, String reason, List<String> risks) {

    public static OpaDecision allow() {
        return new OpaDecision(PolicyOutcome.ALLOW, "OPA_ALLOW", List.of());
    }

    public static OpaDecision deny(String reason) {
        return new OpaDecision(PolicyOutcome.DENY, reason, List.of());
    }
}

