package io.github.straightsang.agentsecurity.mcp.approval;

/* Represents policy and risk results in four levels. */
public enum DecisionType {
    ALLOW,
    ALLOW_LOG,
    REQUIRE_APPROVAL,
    DENY
}
