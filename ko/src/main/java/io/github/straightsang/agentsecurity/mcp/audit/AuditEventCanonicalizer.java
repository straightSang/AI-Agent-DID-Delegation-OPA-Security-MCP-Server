package io.github.straightsang.agentsecurity.mcp.audit;

import java.nio.charset.StandardCharsets;
import org.springframework.stereotype.Component;

/* eventHash와 signature를 제외한 이벤트 필드를 고정 순서의 바이트로 만든다. */
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
