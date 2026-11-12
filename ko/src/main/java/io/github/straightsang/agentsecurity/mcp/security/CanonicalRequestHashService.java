package io.github.straightsang.agentsecurity.mcp.security;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Comparator;
import java.util.Map;
import org.springframework.stereotype.Service;

/* 승인 전후의 요청 내용이 같은지 비교할 수 있도록 요청 전체를 결정적으로 해시한다. */
@Service
public class CanonicalRequestHashService {

    public String hashRequest(
            String actorDid,
            String action,
            String resource,
            Map<String, Object> arguments,
            String requestId,
            String target) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            writeString(output, actorDid);
            writeString(output, action);
            writeString(output, resource);
            writeValue(output, arguments);
            writeString(output, requestId);
            writeString(output, target);
            output.flush();
            return sha256Hex(bytes.toByteArray());
        } catch (IOException exception) {
            throw new IllegalStateException("요청을 정규화하지 못했습니다.", exception);
        }
    }

    public String hashResponse(Object response) {
        String value = response == null ? "null" : response.toString();
        return sha256Hex(value.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private void writeValue(DataOutputStream output, Object value) throws IOException {
        if (value == null) {
            output.writeByte(0);
        } else if (value instanceof String text) {
            output.writeByte(1);
            writeString(output, text);
        } else if (value instanceof Number number) {
            output.writeByte(2);
            writeString(output, number.toString());
        } else if (value instanceof Boolean bool) {
            output.writeByte(3);
            output.writeBoolean(bool);
        } else if (value instanceof Map<?, ?> map) {
            output.writeByte(4);
            var entries = map.entrySet().stream()
                    .map(entry -> Map.entry(String.valueOf(entry.getKey()), entry.getValue()))
                    .sorted(Comparator.comparing(Map.Entry::getKey))
                    .toList();
            output.writeInt(entries.size());
            for (var entry : entries) {
                writeString(output, entry.getKey());
                writeValue(output, entry.getValue());
            }
        } else if (value instanceof Collection<?> collection) {
            output.writeByte(5);
            output.writeInt(collection.size());
            for (Object item : collection) writeValue(output, item);
        } else {
            throw new IllegalArgumentException(
                    "요청 해시에 지원되지 않는 인자 타입입니다: " + value.getClass().getName());
        }
    }

    private void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    private String sha256Hex(byte[] value) {
        try {
            return java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256을 사용할 수 없습니다.", exception);
        }
    }
}
