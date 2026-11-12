package io.github.straightsang.agentsecurity.mcp.state;

import java.time.Instant;
import java.util.Optional;

/** 여러 서버가 Challenge·requestId·승인·폐기 상태를 원자적으로 공유하는 저장소 경계다. */
public interface SecurityStateStore {
    boolean putIfAbsent(String namespace, String key, String value, Instant expiresAt);
    Optional<StateValue> find(String namespace, String key);
    boolean consume(String namespace, String key, Instant now);
    void put(String namespace, String key, String value, Instant expiresAt);
    boolean exists(String namespace, String key, Instant now);

    record StateValue(String value, Instant expiresAt, boolean consumed) {
    }
}
