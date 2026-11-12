package io.github.straightsang.agentsecurity.mcp.state;

import java.time.Instant;
import java.util.Optional;

/** Storage boundary for atomically sharing Challenge, requestId, approval, and revocation state across servers. */
public interface SecurityStateStore {
    boolean putIfAbsent(String namespace, String key, String value, Instant expiresAt);
    Optional<StateValue> find(String namespace, String key);
    boolean consume(String namespace, String key, Instant now);
    void put(String namespace, String key, String value, Instant expiresAt);
    boolean exists(String namespace, String key, Instant now);

    record StateValue(String value, Instant expiresAt, boolean consumed) {
    }
}
