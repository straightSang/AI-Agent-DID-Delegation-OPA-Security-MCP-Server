package io.github.straightsang.agentsecurity.mcp.identity.challenge;

import java.time.Instant;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Issues a one-time HTTP Challenge for the Agent to sign. */
@RestController
@RequestMapping("/identity/challenges")
public class ChallengeController {
    private final ChallengeService challengeService;

    public ChallengeController(ChallengeService challengeService) {
        this.challengeService = challengeService;
    }

    @PostMapping
    public ResponseEntity<ChallengeResponse> issue(@RequestBody ChallengeRequest request) {
        Challenge challenge = challengeService.issue(request.agentDid());
        return ResponseEntity.ok(new ChallengeResponse(
                challenge.challengeId(), challenge.value(), challenge.expiresAt()));
    }

    public record ChallengeRequest(String agentDid) {
    }

    public record ChallengeResponse(String challengeId, String challenge, Instant expiresAt) {
    }
}
