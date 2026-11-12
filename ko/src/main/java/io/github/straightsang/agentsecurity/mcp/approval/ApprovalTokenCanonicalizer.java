package io.github.straightsang.agentsecurity.mcp.approval;

import java.nio.charset.StandardCharsets;
import org.springframework.stereotype.Component;

/* signature를 제외한 승인 토큰 필드를 고정 순서의 바이트로 만든다. */
@Component
public class ApprovalTokenCanonicalizer {
    public byte[] canonicalize(ApprovalToken token) {
        String value = String.join("\n",
                token.approvalId(), token.requestHash(), token.actorDid(), token.target(),
                token.approverDid(), token.issuedAt().toString(), token.expiresAt().toString());
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
