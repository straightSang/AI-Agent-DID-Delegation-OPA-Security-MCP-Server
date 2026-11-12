package io.github.straightsang.agentsecurity.mcp.identity;

import io.github.straightsang.agentsecurity.mcp.domain.AuthenticatedIdentity;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.challenge.Challenge;
import io.github.straightsang.agentsecurity.mcp.identity.challenge.ChallengeService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Set;
import org.springframework.stereotype.Component;

/** DID 소유자가 Challenge를 자신의 개인키로 서명했는지 검증한다. */
@Component
public class AgentProofVerifier {
    private final ChallengeService challengeService;
    private final DidKeyService didKeyService;
    private final CommandIntegrityVerifier commandIntegrityVerifier;

    public AgentProofVerifier(
            ChallengeService challengeService,
            DidKeyService didKeyService,
            CommandIntegrityVerifier commandIntegrityVerifier) {
        this.challengeService = challengeService;
        this.didKeyService = didKeyService;
        this.commandIntegrityVerifier = commandIntegrityVerifier;
    }

    public AuthenticatedIdentity verify(
            String agentDid,
            String challengeId,
            String encodedSignature) {
        Challenge challenge = challengeService.getActive(challengeId, agentDid);
        PublicKey publicKey;
        byte[] signature;
        try {
            publicKey = didKeyService.resolvePublicKey(agentDid);
            signature = Base64.getUrlDecoder().decode(encodedSignature);
        } catch (IllegalArgumentException exception) {
            throw new AccessDeniedException("DID 또는 Challenge 서명 형식이 올바르지 않습니다.");
        }

        boolean valid = commandIntegrityVerifier.verify(
                publicKey,
                challenge.value().getBytes(StandardCharsets.UTF_8),
                signature);
        if (!valid) {
            throw new AccessDeniedException("Agent의 Challenge 서명이 올바르지 않습니다.");
        }

        // 서명에 성공한 Challenge만 사용 완료 처리한다. 실패 요청이 Challenge를 소모하지 않는다.
        challengeService.consume(challengeId, agentDid);
        return new AuthenticatedIdentity(agentDid, agentDid, Set.of("AGENT"), true);
    }
}
