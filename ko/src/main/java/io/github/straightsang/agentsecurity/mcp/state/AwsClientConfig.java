package io.github.straightsang.agentsecurity.mcp.state;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.s3.S3Client;

@Configuration
@Profile("aws")
public class AwsClientConfig {
    @Bean DynamoDbClient dynamoDbClient() { return DynamoDbClient.create(); }
    @Bean KmsClient kmsClient() { return KmsClient.create(); }
    @Bean S3Client s3Client() { return S3Client.create(); }
}
