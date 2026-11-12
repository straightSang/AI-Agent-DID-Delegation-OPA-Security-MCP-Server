package io.github.straightsang.agentsecurity.mcp.audit;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 로컬 실습에서 Merkle 체크포인트 생성을 확인하는 관리 API다. */
@RestController
@RequestMapping("/audit")
@Profile("local")
public class AuditCheckpointController {
    private final AuditLedgerService ledgerService;

    public AuditCheckpointController(AuditLedgerService ledgerService) {
        this.ledgerService = ledgerService;
    }

    @PostMapping("/checkpoints")
    public LedgerCheckpoint checkpoint() {
        return ledgerService.checkpoint();
    }
}
