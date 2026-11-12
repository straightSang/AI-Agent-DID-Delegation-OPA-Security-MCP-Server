package io.github.straightsang.agentsecurity.mcp.audit;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

/* 현재 원장 이벤트를 Merkle 배치로 만들고 외부 앵커 서비스에 전달한다. */
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
