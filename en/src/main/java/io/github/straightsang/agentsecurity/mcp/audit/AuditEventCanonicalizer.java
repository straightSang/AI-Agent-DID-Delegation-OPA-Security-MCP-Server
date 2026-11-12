package io.github.straightsang.agentsecurity.mcp.audit;

import java.nio.charset.StandardCharsets;
import org.springframework.stereotype.Component;

/* Serializes event fields except eventHash and signature in a fixed byte order. */
@Component
public class AuditEventCanonicalizer {
    public byte[] canonicalize(SignedAuditEvent event) {
        String value = String.join("\n",
                Long.toString(event.sequence()),
                event.timestamp().toString(),
                safe(event.requestId()), safe(event.actorDid()), safe(event.action()),
                safe(event.resource()), safe(event.decision()), safe(event.reason()),
                safe(event.requestHash()), safe(event.responseHash()),
                safe(event.previousEventHash()));
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }
}
