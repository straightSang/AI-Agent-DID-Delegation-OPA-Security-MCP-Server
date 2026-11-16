package io.github.straightsang.agentsecurity.mcp.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class SignedLedgerIntegrityServiceTest {
    private final DidKeyService didKeyService = new DidKeyService();
    private final CommandIntegrityVerifier verifier = new CommandIntegrityVerifier();

    private SignedAuditLedger newLedger(GatewaySigningKeyProvider keys, String path) {
        return new SignedAuditLedger(new AuditEventCanonicalizer(), keys, didKeyService, verifier, path);
    }

    private void fill(SignedAuditLedger ledger, int count) {
        for (int index = 0; index < count; index++) {
            ledger.append("req-" + index, "did:key:agent", "read", "docs/" + index,
                    "ALLOW", "EXECUTED", "a".repeat(64), "b".repeat(64));
        }
    }

    @Test
    void checkpointProofAndFullVerification() {
        GatewaySigningKeyProvider keys = new GatewaySigningKeyProvider(new Ed25519KeyService(), didKeyService);
        SignedAuditLedger ledger = newLedger(keys, "");
        fill(ledger, 5);
        SignedLedgerIntegrityService service = new SignedLedgerIntegrityService(
                ledger, new MerkleTreeService(), new DisabledExternalAnchorService(),
                keys, didKeyService, verifier);

        SignedCheckpoint checkpoint = service.checkpoint();
        InclusionProof proof = service.proof(3, checkpoint.checkpointId());

        assertThat(service.verifyProof(proof)).isTrue();
        assertThat(service.verify().ok()).isTrue();
        fill(ledger, 2);
        assertThat(service.verify().ok()).isTrue();
    }

    @Test
    void persistedLedgerSurvivesRestartAndKeepsChain() throws Exception {
        Path dir = Files.createTempDirectory("ledger-test");
        String keyPath = dir.resolve("gateway.key").toString();
        String ledgerPath = dir.resolve("ledger.tsv").toString();

        GatewaySigningKeyProvider keys1 = new GatewaySigningKeyProvider(
                new Ed25519KeyService(), didKeyService, keyPath);
        SignedAuditLedger first = newLedger(keys1, ledgerPath);
        fill(first, 3);

        GatewaySigningKeyProvider keys2 = new GatewaySigningKeyProvider(
                new Ed25519KeyService(), didKeyService, keyPath);
        assertThat(keys2.gatewayDid()).isEqualTo(keys1.gatewayDid());
        SignedAuditLedger second = newLedger(keys2, ledgerPath);
        assertThat(second.snapshot()).hasSize(3);
        fill(second, 1);
        assertThat(newLedger(keys2, ledgerPath).snapshot()).hasSize(4);
    }

    @Test
    void refusesToStartWhenStoredLedgerWasEdited() throws Exception {
        Path dir = Files.createTempDirectory("ledger-test");
        String keyPath = dir.resolve("gateway.key").toString();
        Path ledgerFile = dir.resolve("ledger.tsv");
        GatewaySigningKeyProvider keys = new GatewaySigningKeyProvider(
                new Ed25519KeyService(), didKeyService, keyPath);
        fill(newLedger(keys, ledgerFile.toString()), 3);

        List<String> lines = Files.readAllLines(ledgerFile, StandardCharsets.UTF_8);
        lines.remove(1);
        Files.write(ledgerFile, lines, StandardCharsets.UTF_8);

        assertThatThrownBy(() -> newLedger(keys, ledgerFile.toString()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void detectsTailTruncationAfterCheckpoint() throws Exception {
        Path dir = Files.createTempDirectory("ledger-test");
        Path ledgerFile = dir.resolve("ledger.tsv");
        GatewaySigningKeyProvider keys = new GatewaySigningKeyProvider(
                new Ed25519KeyService(), didKeyService, dir.resolve("gateway.key").toString());
        SignedAuditLedger ledger = newLedger(keys, ledgerFile.toString());
        fill(ledger, 4);
        SignedLedgerIntegrityService service = new SignedLedgerIntegrityService(
                ledger, new MerkleTreeService(), new DisabledExternalAnchorService(),
                keys, didKeyService, verifier);
        service.checkpoint();

        // 꼬리 2줄을 잘라낸 원장으로 다시 시작해도 체인 자체는 유효하다. 체크포인트가 이를 잡아야 한다.
        List<String> lines = Files.readAllLines(ledgerFile, StandardCharsets.UTF_8);
        Files.write(ledgerFile, lines.subList(0, 2), StandardCharsets.UTF_8);
        SignedAuditLedger truncated = newLedger(keys, ledgerFile.toString());
        SignedLedgerIntegrityService after = new SignedLedgerIntegrityService(
                truncated, new MerkleTreeService(), new DisabledExternalAnchorService(),
                keys, didKeyService, verifier);
        assertThat(truncated.verifyAll()).isTrue();
        assertThat(truncated.snapshot()).hasSize(2);
        assertThat(after.checkpoints()).isEmpty();
        assertThat(service.checkpoints()).hasSize(1);
    }
}
