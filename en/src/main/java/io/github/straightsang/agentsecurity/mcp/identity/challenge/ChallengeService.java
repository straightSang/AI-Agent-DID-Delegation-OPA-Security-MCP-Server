package io.github.straightsang.agentsecurity.mcp.identity.challenge;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import io.github.straightsang.agentsecurity.mcp.state.InMemorySecurityStateStore;
import io.github.straightsang.agentsecurity.mcp.state.SecurityStateStore;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

/** Issues Challenges and checks expiry, DID binding, and one-time use. */
@Service
public class ChallengeService {
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(2);
    private static final String NAMESPACE = "challenge";
    private final SecurityStateStore stateStore;
    private final ObjectMapper objectMapper;
    private final SecureRandom secureRandom;
    private final Clock clock;
    private final Duration ttl;

    public ChallengeService() {
        this(new InMemorySecurityStateStore(), new ObjectMapper());
    }

    @Autowired
    public ChallengeService(SecurityStateStore stateStore, ObjectMapper objectMapper) {
        this(stateStore, objectMapper, new SecureRandom(), Clock.systemUTC(), DEFAULT_TTL);
    }

    ChallengeService(SecureRandom secureRandom, Clock clock, Duration ttl) {
        this(new InMemorySecurityStateStore(), new ObjectMapper(),
                secureRandom, clock, ttl);
    }

    private ChallengeService(
            SecurityStateStore stateStore,
            ObjectMapper objectMapper,
            SecureRandom secureRandom,
            Clock clock,
            Duration ttl) {
        this.stateStore = stateStore;
        this.objectMapper = objectMapper;
        this.secureRandom = secureRandom;
        this.clock = clock;
        this.ttl = ttl;
    }

    public Challenge issue(String agentDid) {
        if (agentDid == null || agentDid.isBlank()) {
            throw new IllegalArgumentException("Challenge를 발급할 Agent DID가 없습니다.");
        }
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        Instant issuedAt = Instant.now(clock);
        Challenge challenge = new Challenge(
                UUID.randomUUID().toString(),
                agentDid,
                Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes),
                issuedAt,
                issuedAt.plus(ttl),
                false);
        if (!stateStore.putIfAbsent(
                NAMESPACE, challenge.challengeId(), write(challenge), challenge.expiresAt())) {
            throw new IllegalStateException("Challenge ID 충돌이 발생했습니다.");
        }
        return challenge;
    }

    public Challenge getActive(String challengeId, String agentDid) {
        SecurityStateStore.StateValue stored = stateStore.find(NAMESPACE, challengeId).orElse(null);
        if (stored == null) {
            throw new AccessDeniedException("존재하지 않는 Challenge입니다.");
        }
        Challenge challenge = read(stored.value());
        if (!challenge.agentDid().equals(agentDid)) {
            throw new AccessDeniedException("Challenge가 현재 Agent에게 발급된 것이 아닙니다.");
        }
        if (stored.consumed()) {
            throw new AccessDeniedException("이미 사용된 Challenge입니다.");
        }
        if (!challenge.expiresAt().isAfter(Instant.now(clock))) {
            throw new AccessDeniedException("Challenge가 만료되었습니다.");
        }
        return challenge;
    }

    public void consume(String challengeId, String agentDid) {
        getActive(challengeId, agentDid);
        if (!stateStore.consume(NAMESPACE, challengeId, Instant.now(clock))) {
            throw new AccessDeniedException("이미 사용되었거나 만료된 Challenge입니다.");
        }
    }

    private String write(Challenge challenge) {
        try {
            return objectMapper.writeValueAsString(challenge);
        } catch (JacksonException exception) {
            throw new IllegalStateException("Challenge를 저장하지 못했습니다.", exception);
        }
    }

    private Challenge read(String value) {
        try {
            return objectMapper.readValue(value, Challenge.class);
        } catch (JacksonException exception) {
            throw new IllegalStateException("저장된 Challenge를 읽지 못했습니다.", exception);
        }
    }
}
