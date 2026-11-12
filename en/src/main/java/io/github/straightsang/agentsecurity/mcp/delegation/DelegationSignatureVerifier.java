package io.github.straightsang.agentsecurity.mcp.delegation;

import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.security.PublicKey;
import java.util.Base64;
import org.springframework.stereotype.Component;

/* Resolves the issuer DID public key and verifies that the issuer private key signed the token. */
@Component
public class DelegationSignatureVerifier {
    private final DidKeyService didKeyService;
    private final DelegationTokenCanonicalizer canonicalizer;
    private final CommandIntegrityVerifier integrityVerifier;

    public DelegationSignatureVerifier(
            DidKeyService didKeyService,
            DelegationTokenCanonicalizer canonicalizer,
            CommandIntegrityVerifier integrityVerifier) {
        this.didKeyService = didKeyService;
        this.canonicalizer = canonicalizer;
        this.integrityVerifier = integrityVerifier;
    }

    public void verify(DelegationToken token) {
        try {
            PublicKey issuerPublicKey = didKeyService.resolvePublicKey(token.issuer());
            byte[] signature = Base64.getUrlDecoder().decode(token.signature());
            boolean valid = integrityVerifier.verify(
                    issuerPublicKey, canonicalizer.canonicalize(token), signature);
            if (!valid) {
                throw new AccessDeniedException("위임 토큰의 issuer 서명이 올바르지 않습니다.");
            }
        } catch (AccessDeniedException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new AccessDeniedException("위임 토큰 서명을 검증하지 못했습니다.");
        }
    }
}
