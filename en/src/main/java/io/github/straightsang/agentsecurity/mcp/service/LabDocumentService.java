package io.github.straightsang.agentsecurity.mcp.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.stereotype.Service;

/** Reads only regular files inside the sandbox. */
@Service
public class LabDocumentService {
    private final Path sandboxRoot = Path.of("sandbox").toAbsolutePath().normalize();

    public String read(String requestedPath) {
        if (requestedPath == null || requestedPath.isBlank()) {
            throw new IllegalArgumentException("문서 경로가 없습니다.");
        }

        try {
            // The lexical normalization check quickly blocks ../ traversal.
            Path normalizedTarget = sandboxRoot.resolve(requestedPath).normalize();
            if (!normalizedTarget.startsWith(sandboxRoot)) {
                throw new SecurityException("sandbox 외부 경로입니다.");
            }

            // toRealPath() follows symbolic links to their actual targets.
            // Rejects links whose actual target is outside the sandbox even if the link itself is inside.
            Path realRoot = sandboxRoot.toRealPath();
            Path realTarget = normalizedTarget.toRealPath();
            if (!realTarget.startsWith(realRoot)) {
                throw new SecurityException("심볼릭 링크가 sandbox 외부를 가리킵니다.");
            }
            if (!Files.isRegularFile(realTarget)) {
                throw new IllegalArgumentException("일반 파일이 아닙니다: " + requestedPath);
            }
            return Files.readString(realTarget, StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new IllegalArgumentException("파일이 없거나 실제 경로를 확인할 수 없습니다: " + requestedPath,
                    exception);
        }
    }
}
