package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

/* Builds a Merkle batch from current ledger events and sends it to the external anchor. */
@Service
public class AuditBatchService {
    private final SignedAuditLedger ledger;
    private final MerkleTreeService merkleTreeService;
    private final ExternalAnchorService anchorService;

    public AuditBatchService(
            SignedAuditLedger ledger,
            MerkleTreeService merkleTreeService,
            ExternalAnchorService anchorService) {
        this.ledger = ledger;
        this.merkleTreeService = merkleTreeService;
        this.anchorService = anchorService;
    }

    public AuditBatch createAndAnchorBatch() {
        List<String> hashes = ledger.snapshot().stream()
                .map(SignedAuditEvent::eventHash)
                .toList();
        String root = merkleTreeService.calculateRoot(hashes);
        AuditBatch batch = new AuditBatch(
                UUID.randomUUID().toString(), Instant.now(), hashes, root, null);
        return batch.withReceipt(anchorService.anchor(root));
    }
}
