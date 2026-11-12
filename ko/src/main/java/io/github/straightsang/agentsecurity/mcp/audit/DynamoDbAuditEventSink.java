package io.github.straightsang.agentsecurity.mcp.audit;

import io.github.straightsang.agentsecurity.mcp.state.AwsStateProperties;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

/** 각 인스턴스의 서명 해시 체인을 DynamoDB에 조건부 저장해 중앙 조회와 보존을 제공한다. */
@Component
@Profile("aws")
public class DynamoDbAuditEventSink implements AuditEventSink {
    private final DynamoDbClient dynamo;
    private final String table;

    public DynamoDbAuditEventSink(DynamoDbClient dynamo, AwsStateProperties properties) {
        this.dynamo = dynamo;
        this.table = properties.auditTable();
        if (table == null || table.isBlank()) {
            throw new IllegalStateException("security.aws.audit-table 설정이 필요합니다.");
        }
    }

    @Override
    public void store(AuditLedgerEntry entry) {
        dynamo.putItem(PutItemRequest.builder()
                .tableName(table)
                .item(Map.ofEntries(
                        Map.entry("instanceId", AttributeValue.fromS(entry.instanceId())),
                        Map.entry("sequence", AttributeValue.fromN(Long.toString(entry.sequence()))),
                        Map.entry("previousHash", AttributeValue.fromS(entry.previousHash())),
                        Map.entry("requestHash", AttributeValue.fromS(entry.requestHash())),
                        Map.entry("responseHash", AttributeValue.fromS(entry.responseHash())),
                        Map.entry("actorDid", AttributeValue.fromS(entry.actorDid())),
                        Map.entry("action", AttributeValue.fromS(entry.action())),
                        Map.entry("resource", AttributeValue.fromS(entry.resource())),
                        Map.entry("decision", AttributeValue.fromS(entry.decision())),
                        Map.entry("timestamp", AttributeValue.fromS(entry.timestamp().toString())),
                        Map.entry("eventHash", AttributeValue.fromS(entry.eventHash())),
                        Map.entry("signatureAlgorithm", AttributeValue.fromS(entry.signatureAlgorithm())),
                        Map.entry("signature", AttributeValue.fromS(entry.signature()))))
                .conditionExpression("attribute_not_exists(instanceId) AND attribute_not_exists(#sequence)")
                .expressionAttributeNames(Map.of("#sequence", "sequence"))
                .build());
    }
}
