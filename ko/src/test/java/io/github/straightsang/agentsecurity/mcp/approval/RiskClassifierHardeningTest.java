package io.github.straightsang.agentsecurity.mcp.approval;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class RiskClassifierHardeningTest {
    private final RiskClassifier classifier = new RiskClassifier();

    private DecisionType decide(String path) {
        return classifier.assess("read_lab_document", path, Map.of("path", path), path).decision();
    }

    @Test
    void deniesPathTraversalIncludingEncodedForms() {
        assertThat(decide("../etc/hosts")).isEqualTo(DecisionType.DENY);
        assertThat(decide("docs/../../x")).isEqualTo(DecisionType.DENY);
        assertThat(decide("%2e%2e/secrets-free")).isEqualTo(DecisionType.DENY);
        assertThat(decide("%252e%252e%252fx")).isEqualTo(DecisionType.DENY);
        assertThat(decide("docs\\..\\..\\x")).isEqualTo(DecisionType.DENY);
        assertThat(decide("docs/a.txt%00.png")).isEqualTo(DecisionType.DENY);
    }

    @Test
    void deniesAbsolutePathsAndUrlsToFiles() {
        assertThat(decide("/etc/hostname")).isEqualTo(DecisionType.DENY);
        assertThat(decide("C:\\Windows\\win.ini")).isEqualTo(DecisionType.DENY);
        assertThat(decide("file:///tmp/x")).isEqualTo(DecisionType.DENY);
    }

    @Test
    void deniesCredentialFilesAndSecretsEvenWithFullWidthCharacters() {
        assertThat(decide("home/.env")).isEqualTo(DecisionType.DENY);
        assertThat(decide("keys/id_rsa")).isEqualTo(DecisionType.DENY);
        assertThat(decide("cert/server.pem")).isEqualTo(DecisionType.DENY);
        assertThat(decide("\uFF53\uFF45\uFF43\uFF52\uFF45\uFF54/a.txt")).isEqualTo(DecisionType.DENY);
        assertThat(decide("docs/비밀번호.txt")).isEqualTo(DecisionType.DENY);
    }

    @Test
    void requiresApprovalForExternalTransferAndDestructiveWordsButNotSubstrings() {
        assertThat(decide("personal/list.txt")).isEqualTo(DecisionType.REQUIRE_APPROVAL);
        assertThat(classifier.assess("http_post", "partner", Map.of("url", "https://partner.example"), "partner")
                .decision()).isEqualTo(DecisionType.REQUIRE_APPROVAL);
        assertThat(classifier.assess("delete_file", "docs/a.txt", Map.of(), "docs/a.txt")
                .decision()).isEqualTo(DecisionType.REQUIRE_APPROVAL);
        assertThat(decide("docs/개인정보.txt")).isEqualTo(DecisionType.REQUIRE_APPROVAL);
        assertThat(decide("docs/compost-notes.txt")).isEqualTo(DecisionType.ALLOW);
    }

    @Test
    void allowsOrdinaryReads() {
        assertThat(decide("docs/readme.txt")).isEqualTo(DecisionType.ALLOW);
        assertThat(classifier.assess("calculator_add", "calculator", Map.of("a", 1, "b", 2), "calculator")
                .decision()).isEqualTo(DecisionType.ALLOW);
    }
}
