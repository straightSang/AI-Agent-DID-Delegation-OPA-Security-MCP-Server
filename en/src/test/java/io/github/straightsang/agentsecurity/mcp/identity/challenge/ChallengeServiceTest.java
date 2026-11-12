package io.github.straightsang.agentsecurity.mcp.identity.challenge;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import org.junit.jupiter.api.Test;

class ChallengeServiceTest {
    @Test
    void rejectsConsumedChallenge() {
        ChallengeService service = new ChallengeService();
        Challenge challenge = service.issue("did:key:test");
        service.consume(challenge.challengeId(), challenge.agentDid());
        assertThatThrownBy(() -> service.getActive(challenge.challengeId(), challenge.agentDid()))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("이미 사용된 Challenge입니다.");
    }

    @Test
    void rejectsExpiredChallenge() {
        MutableClock clock = new MutableClock(Instant.parse("2026-11-11T00:00:00Z"));
        ChallengeService service = new ChallengeService(
                new SecureRandom(), clock, Duration.ofSeconds(30));
        Challenge challenge = service.issue("did:key:test");
        clock.advance(Duration.ofSeconds(31));
        assertThatThrownBy(() -> service.getActive(challenge.challengeId(), challenge.agentDid()))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Challenge가 만료되었습니다.");
    }

    private static final class MutableClock extends Clock {
        private Instant instant;
        private MutableClock(Instant instant) { this.instant = instant; }
        private void advance(Duration duration) { instant = instant.plus(duration); }
        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }
}
