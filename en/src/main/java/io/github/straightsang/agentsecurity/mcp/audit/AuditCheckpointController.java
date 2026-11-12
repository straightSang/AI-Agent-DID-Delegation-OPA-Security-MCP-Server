package io.github.straightsang.agentsecurity.mcp.audit;

import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Administrative API for verifying Merkle checkpoint creation in the local lab. */
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
