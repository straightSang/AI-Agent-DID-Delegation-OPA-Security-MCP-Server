package io.github.straightsang.agentsecurity.mcp.audit;

import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/*
 * 로컬 실습에서 체크포인트 생성, 포함 증명, 원장 통합 검증을 확인하는 관리 API다.
 * Gateway가 실제로 기록하는 SignedAuditLedger를 대상으로 한다.
 */
@RestController
@RequestMapping("/audit")
@Profile("local")
public class AuditCheckpointController {
    private final SignedLedgerIntegrityService integrityService;

    public AuditCheckpointController(SignedLedgerIntegrityService integrityService) {
        this.integrityService = integrityService;
    }

    @PostMapping("/checkpoints")
    public SignedCheckpoint checkpoint() {
        return integrityService.checkpoint();
    }

    @GetMapping("/checkpoints")
    public List<SignedCheckpoint> checkpoints() {
        return integrityService.checkpoints();
    }

    @GetMapping("/verify")
    public LedgerVerificationReport verify() {
        return integrityService.verify();
    }

    @GetMapping("/proof")
    public InclusionProof proof(
            @RequestParam("sequence") long sequence,
            @RequestParam("checkpointId") String checkpointId) {
        return integrityService.proof(sequence, checkpointId);
    }

    @PostMapping("/proof/verify")
    public Map<String, Boolean> verifyProof(@RequestBody InclusionProof proof) {
        return Map.of("valid", integrityService.verifyProof(proof));
    }
}
