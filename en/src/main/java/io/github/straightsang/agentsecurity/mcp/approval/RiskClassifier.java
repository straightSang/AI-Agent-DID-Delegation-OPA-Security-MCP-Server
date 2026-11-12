package io.github.straightsang.agentsecurity.mcp.approval;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Service;

/* Classifies whether action, resource, and arguments require user approval. */
@Service
public class RiskClassifier {

    public RiskAssessment assess(
            String action,
            String resource,
            Map<String, Object> arguments,
            String target) {
        String combined = (action + " " + resource + " " + arguments + " " + target)
                .toLowerCase(Locale.ROOT);
        List<String> risks = new ArrayList<>();

        if (containsAny(combined, "secret", "private_key", "credential", "password")) {
            risks.add("비밀정보 또는 자격증명에 접근할 가능성이 있습니다.");
            return new RiskAssessment(
                    RiskLevel.CRITICAL, DecisionType.DENY,
                    action + " 실행", target, List.copyOf(risks));
        }

        if (containsAny(combined, "personal", "email", "phone", "external", "send", "export")) {
            risks.add("개인정보 또는 내부 데이터가 외부로 전달될 수 있습니다.");
            risks.add("전달 후에는 데이터를 회수하기 어려울 수 있습니다.");
            return new RiskAssessment(
                    RiskLevel.HIGH, DecisionType.REQUIRE_APPROVAL,
                    action + " 실행", target, List.copyOf(risks));
        }

        if (containsAny(combined, "write", "update", "modify")) {
            risks.add("파일 또는 시스템 상태가 변경됩니다.");
            return new RiskAssessment(
                    RiskLevel.MEDIUM, DecisionType.ALLOW_LOG,
                    action + " 실행", target, List.copyOf(risks));
        }

        return new RiskAssessment(
                RiskLevel.LOW, DecisionType.ALLOW,
                action + " 실행", target, List.of("읽기 전용 또는 낮은 위험의 요청입니다."));
    }

    private boolean containsAny(String value, String... candidates) {
        for (String candidate : candidates) {
            if (value.contains(candidate)) return true;
        }
        return false;
    }
}
