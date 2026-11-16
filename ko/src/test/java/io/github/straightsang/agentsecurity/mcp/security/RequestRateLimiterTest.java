package io.github.straightsang.agentsecurity.mcp.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.state.InMemorySecurityStateStore;
import org.junit.jupiter.api.Test;

class RequestRateLimiterTest {
    @Test
    void rejectsRequestsOverTheLimitPerAgent() {
        RequestRateLimiter limiter = new RequestRateLimiter(new InMemorySecurityStateStore(), 3);
        for (int index = 0; index < 3; index++) {
            limiter.check("did:key:a");
        }
        assertThatThrownBy(() -> limiter.check("did:key:a")).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> limiter.check("did:key:a")).isInstanceOf(AccessDeniedException.class);
        assertThatCode(() -> limiter.check("did:key:b")).doesNotThrowAnyException();
    }

    @Test
    void zeroDisablesTheLimit() {
        RequestRateLimiter limiter = new RequestRateLimiter(new InMemorySecurityStateStore(), 0);
        for (int index = 0; index < 100; index++) limiter.check("did:key:a");
    }

    @Test
    void limitIsSharedAcrossInstancesThatShareTheStateStore() {
        InMemorySecurityStateStore shared = new InMemorySecurityStateStore();
        RequestRateLimiter first = new RequestRateLimiter(shared, 2);
        RequestRateLimiter second = new RequestRateLimiter(shared, 2);
        first.check("did:key:a");
        second.check("did:key:a");
        assertThatThrownBy(() -> first.check("did:key:a")).isInstanceOf(AccessDeniedException.class);
    }
}
