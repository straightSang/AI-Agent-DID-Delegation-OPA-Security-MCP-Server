package io.github.straightsang.agentsecurity.mcp.state;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** 로컬·테스트용 저장소다. 단일 JVM에서만 공유되므로 운영 프로필에는 사용하지 않는다. */
@Component
@Profile("!aws")
public class InMemorySecurityStateStore implements SecurityStateStore {
    private final ConcurrentHashMap<String, StateValue> values = new ConcurrentHashMap<>();

    @Override
    public boolean putIfAbsent(String namespace, String key, String value, Instant expiresAt) {
        String compoundKey = compound(namespace, key);
        StateValue next = new StateValue(value, expiresAt, false);
        return values.compute(compoundKey, (ignored, current) ->
                current == null || expired(current, Instant.now()) ? next : current) == next;
    }

    @Override
    public Optional<StateValue> find(String namespace, String key) {
        StateValue value = values.get(compound(namespace, key));
        return value == null ? Optional.empty() : Optional.of(value);
    }

    @Override
    public boolean consume(String namespace, String key, Instant now) {
        String compoundKey = compound(namespace, key);
        boolean[] consumed = {false};
        values.computeIfPresent(compoundKey, (ignored, current) -> {
            if (!current.consumed() && !expired(current, now)) {
                consumed[0] = true;
                return new StateValue(current.value(), current.expiresAt(), true);
            }
            return current;
        });
        return consumed[0];
    }

    @Override
    public void put(String namespace, String key, String value, Instant expiresAt) {
        values.put(compound(namespace, key), new StateValue(value, expiresAt, false));
    }

    @Override
    public boolean exists(String namespace, String key, Instant now) {
        StateValue value = values.get(compound(namespace, key));
        return value != null && !expired(value, now);
    }

    private boolean expired(StateValue value, Instant now) {
        return value.expiresAt() != null && !value.expiresAt().isAfter(now);
    }

    private String compound(String namespace, String key) {
        if (namespace == null || namespace.isBlank() || key == null || key.isBlank()) {
            throw new IllegalArgumentException("상태 namespace와 key가 필요합니다.");
        }
        return namespace + "#" + key;
    }
}
