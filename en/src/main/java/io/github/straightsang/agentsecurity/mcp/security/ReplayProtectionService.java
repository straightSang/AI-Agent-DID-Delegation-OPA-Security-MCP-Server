package io.github.straightsang.agentsecurity.mcp.security;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.state.SecurityStateStore;
import io.github.straightsang.agentsecurity.mcp.state.InMemorySecurityStateStore;
import java.time.Duration;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

@Service
public class ReplayProtectionService {
    private static final String NAMESPACE = "request";
    private static final Duration RETENTION = Duration.ofHours(24);
    private final SecurityStateStore stateStore;

    public ReplayProtectionService() {
        this(new InMemorySecurityStateStore());
    }

    @Autowired
    public ReplayProtectionService(SecurityStateStore stateStore) {
        this.stateStore = stateStore;
    }

    public void checkAndConsume(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            throw new AccessDeniedException("requestId가 없습니다.");
        }
        if (!stateStore.putIfAbsent(
                NAMESPACE, requestId, "consumed", Instant.now().plus(RETENTION))) {
            throw new AccessDeniedException("이미 사용된 requestId입니다.");
        }
    }
}
