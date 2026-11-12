package io.github.straightsang.agentsecurity.mcp.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import org.junit.jupiter.api.Test;

class ReplayProtectionServiceTest {

    @Test
    void rejectsReusedRequestId() {
        ReplayProtectionService service = new ReplayProtectionService();
        service.checkAndConsume("req-001");

        assertThatThrownBy(() -> service.checkAndConsume("req-001"))
                .isInstanceOf(AccessDeniedException.class);
    }
}

