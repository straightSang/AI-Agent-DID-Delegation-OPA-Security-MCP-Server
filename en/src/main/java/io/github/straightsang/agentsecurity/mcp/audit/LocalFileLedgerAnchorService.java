package io.github.straightsang.agentsecurity.mcp.audit;

import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** Local verification anchor; it is not WORM, so use S3 Object Lock in production. */
@Component
@Profile("!aws")
public class LocalFileLedgerAnchorService implements LedgerAnchorService {
    private final ObjectMapper mapper;

    public LocalFileLedgerAnchorService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public String anchor(LedgerCheckpoint checkpoint) {
        try {
            Path directory = Path.of("audit-anchors").toAbsolutePath().normalize();
            Files.createDirectories(directory);
            Path target = directory.resolve(checkpoint.checkpointId() + ".json");
            Files.writeString(target, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(checkpoint),
                    StandardOpenOption.CREATE_NEW);
            return target.toString();
        } catch (IOException exception) {
            throw new IllegalStateException("로컬 체크포인트 앵커 저장에 실패했습니다.", exception);
        }
    }
}
