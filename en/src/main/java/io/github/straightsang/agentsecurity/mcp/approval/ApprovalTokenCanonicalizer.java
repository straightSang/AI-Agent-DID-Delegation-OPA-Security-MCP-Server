package io.github.straightsang.agentsecurity.mcp.approval;

import java.nio.charset.StandardCharsets;
import org.springframework.stereotype.Component;

/* Serializes approval-token fields except signature into a fixed byte order. */
@Component
public class ApprovalTokenCanonicalizer {
    public byte[] canonicalize(ApprovalToken token) {
        String value = String.join("\n",
                token.approvalId(), token.requestHash(), token.actorDid(), token.target(),
                token.approverDid(), token.issuedAt().toString(), token.expiresAt().toString());
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
