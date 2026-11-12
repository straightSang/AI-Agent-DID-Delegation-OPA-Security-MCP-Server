package io.github.straightsang.agentsecurity.mcp.audit;

import tools.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** 로컬 검증용 앵커다. WORM이 아니므로 운영에서는 S3 Object Lock 구현을 사용한다. */
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
