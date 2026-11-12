package io.github.straightsang.agentsecurity.mcp.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.domain.AuthenticatedIdentity;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.challenge.Challenge;
import io.github.straightsang.agentsecurity.mcp.identity.challenge.ChallengeService;
import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class AgentProofVerifierTest {
    private final Ed25519KeyService keyService = new Ed25519KeyService();
    private final DidKeyService didKeyService = new DidKeyService();
    private final ChallengeService challengeService = new ChallengeService();
    private final AgentProofVerifier verifier = new AgentProofVerifier(
            challengeService, didKeyService, new CommandIntegrityVerifier());

    @Test
    void acceptsProofFromMatchingPrivateKey() throws Exception {
        KeyPair agentKeys = keyService.generateKeyPair();
        String did = didKeyService.createDid(agentKeys.getPublic());
        Challenge challenge = challengeService.issue(did);
        String signature = sign(agentKeys, challenge.value());
        AuthenticatedIdentity identity = verifier.verify(did, challenge.challengeId(), signature);
        assertThat(identity.authenticated()).isTrue();
        assertThat(identity.did()).isEqualTo(did);
    }

    @Test
    void rejectsProofFromDifferentPrivateKey() throws Exception {
        KeyPair agentKeys = keyService.generateKeyPair();
        KeyPair attackerKeys = keyService.generateKeyPair();
        String did = didKeyService.createDid(agentKeys.getPublic());
        Challenge challenge = challengeService.issue(did);
        String attackerSignature = sign(attackerKeys, challenge.value());
        assertThatThrownBy(() -> verifier.verify(did, challenge.challengeId(), attackerSignature))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Agent의 Challenge 서명이 올바르지 않습니다.");
    }

    @Test
    void rejectsReusingSuccessfulChallenge() throws Exception {
        KeyPair keys = keyService.generateKeyPair();
        String did = didKeyService.createDid(keys.getPublic());
        Challenge challenge = challengeService.issue(did);
        String signature = sign(keys, challenge.value());
        verifier.verify(did, challenge.challengeId(), signature);
        assertThatThrownBy(() -> verifier.verify(did, challenge.challengeId(), signature))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("이미 사용된 Challenge입니다.");
    }

    private String sign(KeyPair keyPair, String value) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keyPair.getPrivate());
        signer.update(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }
}
