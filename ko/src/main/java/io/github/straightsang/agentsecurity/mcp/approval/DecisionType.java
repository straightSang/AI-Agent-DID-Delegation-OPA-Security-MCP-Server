package io.github.straightsang.agentsecurity.mcp.approval;

/* 정책과 위험 분류 결과를 네 단계로 표현한다. */
public enum DecisionType {
    ALLOW,
    ALLOW_LOG,
    REQUIRE_APPROVAL,
    DENY
}
