package io.github.straightsang.agentsecurity.mcp.domain;

import java.util.Set;

public record AuthenticatedIdentity(
        String did,
        String jwtSubject,
        Set<String> roles,
        boolean authenticated) {
}

