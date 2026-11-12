package io.github.straightsang.agentsecurity.mcp.approval;

import java.util.List;
import org.springframework.stereotype.Service;

/** 행동 이름과 리소스를 사람이 이해할 수 있는 승인 위험 설명으로 변환한다. */
@Service
public class RiskAssessmentService {
    public RiskAssessment assess(String action, String resource) {
        if (action == null) return new RiskAssessment(
                RiskLevel.HIGH, DecisionType.DENY,
                "알 수 없는 행동", resource, List.of("행동을 식별할 수 없습니다."));
        if (action.contains("send") || action.contains("publish") || action.contains("delete")) {
            return new RiskAssessment(RiskLevel.HIGH, DecisionType.REQUIRE_APPROVAL,
                    action, resource,
                    List.of("외부 전송 또는 삭제는 되돌리기 어렵습니다.",
                            "개인정보·기밀정보가 포함됐는지 확인해야 합니다."));
        }
        if (action.contains("write") || action.contains("update")) {
            return new RiskAssessment(RiskLevel.MEDIUM, DecisionType.ALLOW_LOG,
                    action, resource,
                    List.of("리소스 내용이 변경됩니다.", "변경 범위와 복구 방법을 확인해야 합니다."));
        }
        return new RiskAssessment(RiskLevel.LOW, DecisionType.ALLOW,
                action, resource,
                List.of("읽기 또는 계산 결과가 감사 원장에 기록됩니다."));
    }
}
