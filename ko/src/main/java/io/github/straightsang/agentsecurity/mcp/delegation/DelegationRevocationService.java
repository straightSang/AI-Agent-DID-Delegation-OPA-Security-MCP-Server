package io.github.straightsang.agentsecurity.mcp.delegation;

import io.github.straightsang.agentsecurity.mcp.state.SecurityStateStore;
import io.github.straightsang.agentsecurity.mcp.state.InMemorySecurityStateStore;
import java.time.Duration;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

/* 폐기된 tokenId를 저장한다. 운영 환경에서는 Redis나 DB로 교체해야 한다. */
@Service
public class DelegationRevocationService {
    private static final String NAMESPACE = "revocation";
    private final SecurityStateStore stateStore;

    public DelegationRevocationService() {
        this(new InMemorySecurityStateStore());
    }

    @Autowired
    public DelegationRevocationService(SecurityStateStore stateStore) {
        this.stateStore = stateStore;
    }

    public void revoke(String tokenId) {
        if (tokenId == null || tokenId.isBlank()) {
            throw new IllegalArgumentException("폐기할 tokenId가 없습니다.");
        }
        stateStore.put(NAMESPACE, tokenId, "revoked", Instant.now().plus(Duration.ofDays(3650)));
    }

    public boolean isRevoked(String tokenId) {
        return stateStore.exists(NAMESPACE, tokenId, Instant.now());
    }
}
