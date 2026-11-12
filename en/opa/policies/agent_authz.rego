package agent.authz

import rego.v1

# OPA denies by default and permits execution only when every condition is explicitly true.
default allow := false

allow if {
    input.authenticated == true
    input.delegationValid == true
    input.actor == input.delegation.subject
    input.action in input.delegation.actions
    input.resource in input.delegation.resources
}

# OPA returns four Gateway outcomes instead of a simple boolean.
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
