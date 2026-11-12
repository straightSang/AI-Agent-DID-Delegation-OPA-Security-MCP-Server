package io.github.straightsang.agentsecurity.mcp.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CanonicalRequestHashServiceTest {
    private final CanonicalRequestHashService service = new CanonicalRequestHashService();

    @Test
    void mapOrderDoesNotChangeRequestHash() {
        Map<String, Object> first = new LinkedHashMap<>();
        first.put("a", 1);
        first.put("b", 2);
        Map<String, Object> second = new LinkedHashMap<>();
        second.put("b", 2);
        second.put("a", 1);

        String firstHash = service.hashRequest(
                "did:key:agent", "calculator_add", "calculator", first, "req-1", "calculator");
        String secondHash = service.hashRequest(
                "did:key:agent", "calculator_add", "calculator", second, "req-1", "calculator");

        assertThat(firstHash).isEqualTo(secondHash);
    }

    @Test
    void changedArgumentChangesRequestHash() {
        String first = service.hashRequest(
                "did:key:agent", "calculator_add", "calculator", Map.of("a", 1), "req-1", "calculator");
        String changed = service.hashRequest(
                "did:key:agent", "calculator_add", "calculator", Map.of("a", 2), "req-1", "calculator");
        assertThat(first).isNotEqualTo(changed);
    }
}
