package io.github.straightsang.agentsecurity.mcp.audit;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.straightsang.agentsecurity.mcp.crypto.LocalEd25519SigningService;
import org.junit.jupiter.api.Test;

class AuditLedgerServiceTest {
    @Test
    void linksEntriesAndAnchorsMerkleRoot() {
        AuditLedgerService service = new AuditLedgerService(
                new LocalEd25519SigningService(), new MerkleTreeService(),
                checkpoint -> "memory://" + checkpoint.merkleRoot(), entry -> { });

        AuditLedgerEntry first = service.append(
                "request-1", "response-1", "did:key:a", "read", "doc", "ALLOW");
        AuditLedgerEntry second = service.append(
                "request-2", "response-2", "did:key:a", "read", "doc", "ALLOW");
        LedgerCheckpoint checkpoint = service.checkpoint();

        assertThat(second.previousHash()).isEqualTo(first.eventHash());
        assertThat(checkpoint.firstSequence()).isEqualTo(1);
        assertThat(checkpoint.lastSequence()).isEqualTo(2);
        assertThat(checkpoint.anchorReceipt()).startsWith("memory://");
        assertThat(service.verifyChain()).isTrue();
    }
}
