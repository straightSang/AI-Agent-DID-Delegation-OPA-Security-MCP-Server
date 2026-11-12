package io.github.straightsang.agentsecurity.mcp.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class LabDocumentServiceTest {
    @Test
    void rejectsLexicalPathTraversal() {
        LabDocumentService service = new LabDocumentService();
        assertThatThrownBy(() -> service.read("../secret.txt"))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void rejectsSymlinkWhoseRealTargetIsOutsideSandbox() throws Exception {
        Path sandbox = Path.of("sandbox").toAbsolutePath().normalize();
        Files.createDirectories(sandbox);
        Path outside = Files.createTempFile("agent-security-outside-", ".txt");
        Path link = sandbox.resolve("escape-" + UUID.randomUUID() + ".txt");
        try {
            Files.writeString(outside, "secret");
            Files.createSymbolicLink(link, outside);
            LabDocumentService service = new LabDocumentService();
            assertThatThrownBy(() -> service.read(link.getFileName().toString()))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("심볼릭 링크");
        } finally {
            Files.deleteIfExists(link);
            Files.deleteIfExists(outside);
        }
    }
}
