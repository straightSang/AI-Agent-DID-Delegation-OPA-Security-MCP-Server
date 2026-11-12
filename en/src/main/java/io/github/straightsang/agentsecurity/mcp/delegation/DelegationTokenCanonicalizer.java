package io.github.straightsang.agentsecurity.mcp.delegation;

import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.stereotype.Component;

/*
 * Produces deterministic bytes before and after signing.
 * Sorts unordered sets and excludes the signature field from the signed payload.
 */
@Component
public class DelegationTokenCanonicalizer {

    public byte[] canonicalize(DelegationToken token) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);

            writeString(output, token.tokenId());
            writeNullableString(output, token.parentTokenId());
            writeString(output, token.issuer());
            writeString(output, token.subject());
            writeString(output, token.audience());
            writeSet(output, token.actions());
            writeSet(output, token.resources());
            writeInstant(output, token.issuedAt());
            writeInstant(output, token.expiresAt());
            output.writeInt(token.delegationDepth());
            output.flush();
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("위임 토큰을 정규화하지 못했습니다.", exception);
        }
    }

    private void writeSet(DataOutputStream output, Set<String> values) throws IOException {
        TreeSet<String> sortedValues = new TreeSet<>(values);
        output.writeInt(sortedValues.size());
        for (String value : sortedValues) {
            writeString(output, value);
        }
    }

    private void writeInstant(DataOutputStream output, Instant value) throws IOException {
        output.writeLong(value.getEpochSecond());
        output.writeInt(value.getNano());
    }

    private void writeNullableString(DataOutputStream output, String value) throws IOException {
        output.writeBoolean(value != null);
        if (value != null) writeString(output, value);
    }

    private void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }
}
