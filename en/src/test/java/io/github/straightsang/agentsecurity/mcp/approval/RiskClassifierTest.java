package io.github.straightsang.agentsecurity.mcp.approval;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class RiskClassifierTest {
    private final RiskClassifier classifier = new RiskClassifier();

    @Test
    void requiresApprovalForPersonalData() {
        RiskAssessment result = classifier.assess(
                "read_lab_document", "personal/customer.txt",
                Map.of("path", "personal/customer.txt"), "external-partner");
        assertThat(result.decision()).isEqualTo(DecisionType.REQUIRE_APPROVAL);
        assertThat(result.riskLevel()).isEqualTo(RiskLevel.HIGH);
    }

    @Test
    void deniesSecrets() {
        RiskAssessment result = classifier.assess(
                "read_lab_document", "secret/private_key.txt",
                Map.of(), "local");
        assertThat(result.decision()).isEqualTo(DecisionType.DENY);
    }
}
