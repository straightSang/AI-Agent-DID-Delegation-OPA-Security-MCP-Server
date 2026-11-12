package io.github.straightsang.agentsecurity.mcp.audit;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import io.github.straightsang.agentsecurity.mcp.state.AwsStateProperties;
import java.time.Instant;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ObjectLockMode;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/** 서명된 Merkle 체크포인트를 S3 Object Lock COMPLIANCE 모드로 외부 고정한다. */
@Component
@Profile("aws")
public class S3ObjectLockLedgerAnchorService implements LedgerAnchorService {
    private final S3Client s3;
    private final ObjectMapper mapper;
    private final AwsStateProperties properties;

    public S3ObjectLockLedgerAnchorService(
            S3Client s3, ObjectMapper mapper, AwsStateProperties properties) {
        this.s3 = s3;
        this.mapper = mapper;
        this.properties = properties;
    }

    @Override
    public String anchor(LedgerCheckpoint checkpoint) {
        String key = "checkpoints/" + checkpoint.instanceId() + "/" + checkpoint.checkpointId() + ".json";
        try {
            byte[] body = mapper.writeValueAsBytes(checkpoint);
            s3.putObject(PutObjectRequest.builder()
                            .bucket(properties.anchorBucket()).key(key)
                            .contentType("application/json")
                            .objectLockMode(ObjectLockMode.COMPLIANCE)
                            .objectLockRetainUntilDate(Instant.now().plusSeconds(
                                    Math.max(1, properties.anchorRetentionDays()) * 86400L))
                            .build(),
                    RequestBody.fromBytes(body));
            return "s3://" + properties.anchorBucket() + "/" + key;
        } catch (JacksonException exception) {
            throw new IllegalStateException("체크포인트 직렬화에 실패했습니다.", exception);
        }
    }
}
