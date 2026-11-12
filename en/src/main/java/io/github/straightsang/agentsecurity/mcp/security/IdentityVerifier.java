package io.github.straightsang.agentsecurity.mcp.security;

import io.github.straightsang.agentsecurity.mcp.domain.AuthenticatedIdentity;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import org.springframework.stereotype.Component;

@Component
public class IdentityVerifier {

    public void verify(AuthenticatedIdentity identity) {
        if (identity == null || !identity.authenticated()) {
            throw new AccessDeniedException("인증되지 않은 호출자입니다.");
        }
        if (identity.did() == null || identity.did().isBlank()) {
            throw new AccessDeniedException("호출자 DID가 없습니다.");
        }
    }
}

