package io.github.straightsang.agentsecurity.mcp.security;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.state.SecurityStateStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/*
 * Agent DID별 분당 요청 수 제한이다. 탈취된 Agent나 폭주하는 Agent가 단시간에 많이 호출하는 것을 막는다.
 * 60초 창마다 1..N번 자리를 SecurityStateStore.putIfAbsent로 선점한다(원자적이라 서버가 여러 대여도 한도가 지켜진다).
 * 창이 가득 차면 "가득 참" 표지를 남겨 이후 요청은 저장소를 한 번만 조회하고 거부한다.
 * 호출 한 번이 최대 N번의 저장소 접근을 쓸 수 있으므로, 트래픽이 큰 운영 환경에서는 Redis INCR 등 원자 카운터로 바꾼다.
 * perMinute가 0 이하면 제한하지 않는다.
 */
@Service
public class RequestRateLimiter {
    private static final String NAMESPACE = "ratelimit";
    private static final String FULL_NAMESPACE = "ratelimit-full";
    private static final long WINDOW_SECONDS = 60;

    private final SecurityStateStore stateStore;
    private final int perMinute;
    private final Clock clock;
    private final ConcurrentHashMap<String, Integer> slotHints = new ConcurrentHashMap<>();

    @Autowired
    public RequestRateLimiter(
            SecurityStateStore stateStore,
            @Value("${security.rate-limit.per-minute:60}") int perMinute) {
        this(stateStore, perMinute, Clock.systemUTC());
    }

    RequestRateLimiter(SecurityStateStore stateStore, int perMinute, Clock clock) {
        this.stateStore = stateStore;
        this.perMinute = perMinute;
        this.clock = clock;
    }

    public void check(String actorDid) {
        if (perMinute <= 0) return;
        Instant now = Instant.now(clock);
        long window = now.getEpochSecond() / WINDOW_SECONDS;
        Instant expiresAt = Instant.ofEpochSecond((window + 1) * WINDOW_SECONDS).plus(Duration.ofMinutes(1));
        String windowKey = actorDid + "|" + window;
        if (stateStore.exists(FULL_NAMESPACE, windowKey, now)) throw limited();

        slotHints.keySet().removeIf(key -> !key.endsWith("|" + window));
        int start = Math.max(1, slotHints.getOrDefault(windowKey, 1));
        for (int slot = start; slot <= perMinute; slot++) {
            if (stateStore.putIfAbsent(NAMESPACE, windowKey + "|" + slot, "1", expiresAt)) {
                slotHints.put(windowKey, slot);
                return;
            }
        }
        stateStore.put(FULL_NAMESPACE, windowKey, "full", expiresAt);
        throw limited();
    }

    private AccessDeniedException limited() {
        return new AccessDeniedException("요청 한도(분당 " + perMinute + "회)를 넘었습니다. 잠시 뒤 다시 시도하세요.");
    }
}
