package agent.authz

import rego.v1

# OPA는 기본 거부한다. 모든 조건이 명시적으로 참일 때만 실행을 허용한다.
default allow := false

allow if {
    input.authenticated == true
    input.delegationValid == true
    input.actor == input.delegation.subject
    input.action in input.delegation.actions
    input.resource in input.delegation.resources
}

# OPA는 단순 boolean 대신 Gateway가 후속 처리할 4가지 결과를 반환한다.
default decision := {"outcome": "DENY", "reason": "OPA_DENY", "risks": []}

decision := {"outcome": "REQUIRE_APPROVAL", "reason": "HIGH_RISK_ACTION", "risks": ["외부 전송 또는 삭제는 되돌리기 어렵습니다."]} if {
    allow
    high_risk
}

decision := {"outcome": "ALLOW_LOG", "reason": "MUTATION_RECORDED", "risks": ["리소스가 변경됩니다."]} if {
    allow
    mutation
    not high_risk
}

decision := {"outcome": "ALLOW", "reason": "OPA_ALLOW", "risks": []} if {
    allow
    not high_risk
    not mutation
}

high_risk if {
    some keyword in {"send", "publish", "delete"}
    contains(input.action, keyword)
}

mutation if {
    some keyword in {"write", "update"}
    contains(input.action, keyword)
}
