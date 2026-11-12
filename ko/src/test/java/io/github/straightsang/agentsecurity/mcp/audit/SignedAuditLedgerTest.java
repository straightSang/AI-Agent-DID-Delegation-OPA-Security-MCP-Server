package io.github.straightsang.agentsecurity.mcp.audit;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.util.List;
import org.junit.jupiter.api.Test;

class SignedAuditLedgerTest {
    @Test
    void linksAndVerifiesSignedEvents() {
        DidKeyService didKeyService = new DidKeyService();
        GatewaySigningKeyProvider keys = new GatewaySigningKeyProvider(
                new Ed25519KeyService(), didKeyService);
        SignedAuditLedger ledger = new SignedAuditLedger(
                new AuditEventCanonicalizer(), keys, didKeyService,
                new CommandIntegrityVerifier());

        SignedAuditEvent first = ledger.append(
                "req-1", "did:key:agent", "read", "docs/a.txt",
                "ALLOW", "EXECUTED", "a".repeat(64), "b".repeat(64));
        SignedAuditEvent second = ledger.append(
                "req-2", "did:key:agent", "read", "docs/b.txt",
                "DENY", "OPA_DENY", "c".repeat(64), "d".repeat(64));

        assertThat(second.previousEventHash()).isEqualTo(first.eventHash());
        assertThat(ledger.verifyAll()).isTrue();
    }

    @Test
    void createsMerkleRootAndDisabledAnchorReceipt() {
        MerkleTreeService merkle = new MerkleTreeService();
        String root = merkle.calculateRoot(List.of("a".repeat(64), "b".repeat(64)));
        assertThat(root).hasSize(64);
        assertThat(new DisabledExternalAnchorService().anchor(root))
                .isEqualTo("ANCHOR_DISABLED:" + root);
    }
}
