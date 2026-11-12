package io.github.straightsang.agentsecurity.mcp.delegation;

import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.security.DelegationVerifier;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/*
 * Creates root and attenuated child tokens with Ed25519 signatures for the lab environment.
 * In production, sign in an Agent-side KMS or HSM instead of sending a PrivateKey to the server.
 */
@Service
public class DelegationTokenService {
    private final DelegationTokenCanonicalizer canonicalizer;
    private final DelegationVerifier verifier;
    private final Clock clock;

    /* Explicitly marks the production constructor for Spring; the Clock constructor is test-only. */
    @Autowired
    public DelegationTokenService(
            DelegationTokenCanonicalizer canonicalizer,
            DelegationVerifier verifier) {
        this(canonicalizer, verifier, Clock.systemUTC());
    }

    DelegationTokenService(
            DelegationTokenCanonicalizer canonicalizer,
            DelegationVerifier verifier,
            Clock clock) {
        this.canonicalizer = canonicalizer;
        this.verifier = verifier;
        this.clock = clock;
    }

    public DelegationToken issueRoot(
            String issuer,
            String subject,
            String audience,
            Set<String> actions,
            Set<String> resources,
            Instant expiresAt,
            PrivateKey issuerPrivateKey) {
        DelegationToken unsigned = new DelegationToken(
                UUID.randomUUID().toString(), null, issuer, subject, audience,
                Set.copyOf(actions), Set.copyOf(resources), Instant.now(clock),
                expiresAt, 0, null);
        return sign(unsigned, issuerPrivateKey);
    }

    public DelegationToken delegate(
            DelegationToken parent,
            String childSubject,
            Set<String> childActions,
            Set<String> childResources,
            Instant childExpiresAt,
            PrivateKey delegatingAgentPrivateKey) {
        verifier.verifyToken(parent);
        DelegationToken unsigned = new DelegationToken(
                UUID.randomUUID().toString(), parent.tokenId(), parent.subject(), childSubject,
                parent.audience(), Set.copyOf(childActions), Set.copyOf(childResources),
                Instant.now(clock), childExpiresAt, parent.delegationDepth() + 1, null);
        DelegationToken signed = sign(unsigned, delegatingAgentPrivateKey);
        verifier.verifyToken(signed);
        verifier.verifyAttenuation(parent, signed);
        return signed;
    }

    public DelegationToken sign(DelegationToken unsignedToken, PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("위임 토큰에 서명할 개인키가 없습니다.");
        }
        DelegationToken canonicalToken = unsignedToken.withSignature(null);
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(canonicalizer.canonicalize(canonicalToken));
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
            return unsignedToken.withSignature(signature);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Ed25519 알고리즘을 사용할 수 없습니다.", exception);
        } catch (InvalidKeyException exception) {
            throw new IllegalArgumentException("Ed25519 서명에 사용할 수 없는 개인키입니다.", exception);
        } catch (SignatureException exception) {
            throw new IllegalStateException("위임 토큰 서명에 실패했습니다.", exception);
        }
    }
}
