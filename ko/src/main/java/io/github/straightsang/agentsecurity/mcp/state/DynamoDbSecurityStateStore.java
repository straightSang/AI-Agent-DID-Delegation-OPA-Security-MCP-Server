package io.github.straightsang.agentsecurity.mcp.state;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/** DynamoDB 조건부 쓰기로 여러 인스턴스의 일회 사용을 하나의 원자 연산으로 만든다. */
@Component
@Profile("aws")
public class DynamoDbSecurityStateStore implements SecurityStateStore {
    private final DynamoDbClient dynamo;
    private final String table;

    public DynamoDbSecurityStateStore(DynamoDbClient dynamo, AwsStateProperties properties) {
        this.dynamo = dynamo;
        this.table = require(properties.stateTable(), "security.aws.state-table");
    }

    @Override
    public boolean putIfAbsent(String namespace, String key, String value, Instant expiresAt) {
        try {
            dynamo.putItem(PutItemRequest.builder()
                    .tableName(table)
                    .item(item(namespace, key, value, expiresAt, false))
                    .conditionExpression("attribute_not_exists(#ns) AND attribute_not_exists(#key)")
                    .expressionAttributeNames(Map.of("#ns", "namespace", "#key", "stateKey"))
                    .build());
            return true;
        } catch (ConditionalCheckFailedException exception) {
            return false;
        }
    }

    @Override
    public Optional<StateValue> find(String namespace, String key) {
        Map<String, AttributeValue> item = dynamo.getItem(GetItemRequest.builder()
                        .tableName(table).key(key(namespace, key)).consistentRead(true).build())
                .item();
        if (item == null || item.isEmpty()) return Optional.empty();
        return Optional.of(new StateValue(
                item.get("value").s(),
                Instant.ofEpochSecond(Long.parseLong(item.get("expiresAt").n())),
                item.get("consumed").bool()));
    }

    @Override
    public boolean consume(String namespace, String key, Instant now) {
        try {
            dynamo.updateItem(UpdateItemRequest.builder()
                    .tableName(table).key(key(namespace, key))
                    .updateExpression("SET #consumed = :true")
                    .conditionExpression("#consumed = :false AND #expires > :now")
                    .expressionAttributeNames(Map.of("#consumed", "consumed", "#expires", "expiresAt"))
                    .expressionAttributeValues(Map.of(
                            ":true", AttributeValue.fromBool(true),
                            ":false", AttributeValue.fromBool(false),
                            ":now", AttributeValue.fromN(Long.toString(now.getEpochSecond()))))
                    .build());
            return true;
        } catch (ConditionalCheckFailedException exception) {
            return false;
        }
    }

    @Override
    public void put(String namespace, String key, String value, Instant expiresAt) {
        dynamo.putItem(PutItemRequest.builder().tableName(table)
                .item(item(namespace, key, value, expiresAt, false)).build());
    }

    @Override
    public boolean exists(String namespace, String key, Instant now) {
        return find(namespace, key)
                .filter(value -> value.expiresAt().isAfter(now))
                .isPresent();
    }

    private Map<String, AttributeValue> item(
            String namespace, String key, String value, Instant expiresAt, boolean consumed) {
        return Map.of(
                "namespace", AttributeValue.fromS(namespace),
                "stateKey", AttributeValue.fromS(key),
                "value", AttributeValue.fromS(value == null ? "" : value),
                "expiresAt", AttributeValue.fromN(Long.toString(expiresAt.getEpochSecond())),
                "consumed", AttributeValue.fromBool(consumed));
    }

    private Map<String, AttributeValue> key(String namespace, String key) {
        return Map.of("namespace", AttributeValue.fromS(namespace), "stateKey", AttributeValue.fromS(key));
    }

    private String require(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalStateException(name + " 설정이 필요합니다.");
        return value;
    }
}
