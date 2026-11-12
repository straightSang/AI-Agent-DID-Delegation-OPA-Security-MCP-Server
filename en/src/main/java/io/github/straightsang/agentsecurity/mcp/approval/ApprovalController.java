package io.github.straightsang.agentsecurity.mcp.approval;

import io.github.straightsang.agentsecurity.mcp.security.CanonicalRequestHashService;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/* Prepares the risk explanation and requestHash shown by an approval UI or plugin. */
@RestController
@RequestMapping("/approval")
public class ApprovalController {
    private final RiskClassifier riskClassifier;
    private final CanonicalRequestHashService requestHashService;

    public ApprovalController(
            RiskClassifier riskClassifier,
            CanonicalRequestHashService requestHashService) {
        this.riskClassifier = riskClassifier;
        this.requestHashService = requestHashService;
    }

    @PostMapping("/prepare")
    public ResponseEntity<ApprovalPreparation> prepare(@RequestBody ApprovalRequest request) {
        String requestHash = requestHashService.hashRequest(
                request.actorDid(), request.action(), request.resource(), request.arguments(),
                request.requestId(), request.target());
        RiskAssessment assessment = riskClassifier.assess(
                request.action(), request.resource(), request.arguments(), request.target());
        return ResponseEntity.ok(new ApprovalPreparation(requestHash, assessment));
    }

    public record ApprovalRequest(
            String actorDid,
            String action,
            String resource,
            Map<String, Object> arguments,
            String requestId,
            String target) {
    }

    public record ApprovalPreparation(String requestHash, RiskAssessment assessment) {
    }
}
