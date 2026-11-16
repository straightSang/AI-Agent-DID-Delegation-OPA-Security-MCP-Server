package io.github.straightsang.agentsecurity.mcp.audit;

import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/*
 * Gateway가 실제로 쓰는 SignedAuditLedger 위에 체크포인트, 포함 증명, 통합 검증을 제공한다.
 * 체크포인트마다 Merkle root를 외부 앵커(OpenTimestamps 등)에 고정하므로, 나중에 로그 전체를
 * 다시 써도 앵커된 root와 맞지 않아 탐지된다. 앵커 이후에 추가된 구간은 다음 체크포인트 전까지 보호되지 않는다.
 */
@Service
public class SignedLedgerIntegrityService {
    private final SignedAuditLedger ledger;
    private final MerkleTreeService merkleTreeService;
    private final ExternalAnchorService anchorService;
    private final GatewaySigningKeyProvider keyProvider;
    private final DidKeyService didKeyService;
    private final CommandIntegrityVerifier integrityVerifier;
    private final Clock clock;
    private final List<SignedCheckpoint> checkpoints = new ArrayList<>();

    @Autowired
    public SignedLedgerIntegrityService(
            SignedAuditLedger ledger,
            MerkleTreeService merkleTreeService,
            ExternalAnchorService anchorService,
            GatewaySigningKeyProvider keyProvider,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier) {
        this(ledger, merkleTreeService, anchorService, keyProvider, didKeyService,
                integrityVerifier, Clock.systemUTC());
    }

    SignedLedgerIntegrityService(
            SignedAuditLedger ledger,
            MerkleTreeService merkleTreeService,
            ExternalAnchorService anchorService,
            GatewaySigningKeyProvider keyProvider,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            Clock clock) {
        this.ledger = ledger;
        this.merkleTreeService = merkleTreeService;
        this.anchorService = anchorService;
        this.keyProvider = keyProvider;
        this.didKeyService = didKeyService;
        this.integrityVerifier = integrityVerifier;
        this.clock = clock;
    }

    /* 현재까지의 원장을 root 하나로 고정하고 서명한 뒤 외부 앵커에 게시한다. */
    public synchronized SignedCheckpoint checkpoint() {
        List<SignedAuditEvent> events = ledger.snapshot();
        if (events.isEmpty()) {
            throw new IllegalStateException("체크포인트를 만들 원장 항목이 없습니다.");
        }
        if (!ledger.verifyAll()) {
            throw new IllegalStateException("원장 체인이 이미 손상되어 체크포인트를 만들 수 없습니다.");
        }
        String root = merkleTreeService.rfc6962Root(eventHashes(events, events.size()));
        String head = events.getLast().eventHash();
        String checkpointId = UUID.randomUUID().toString();
        Instant createdAt = Instant.now(clock);
        String gatewayDid = keyProvider.gatewayDid();
        String signature = sign(canonical(
                checkpointId, events.size(), root, head, createdAt, gatewayDid));
        String receipt = anchorService.anchor(root);
        SignedCheckpoint checkpoint = new SignedCheckpoint(
                checkpointId, events.size(), root, head, createdAt, gatewayDid, signature, receipt);
        checkpoints.add(checkpoint);
        return checkpoint;
    }

    public synchronized List<SignedCheckpoint> checkpoints() {
        return List.copyOf(checkpoints);
    }

    /* sequence번째 이벤트가 해당 체크포인트에 포함됨을 보이는 증명을 만든다. */
    public synchronized InclusionProof proof(long sequence, String checkpointId) {
        SignedCheckpoint checkpoint = checkpoints.stream()
                .filter(candidate -> candidate.checkpointId().equals(checkpointId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 체크포인트입니다."));
        if (sequence < 1 || sequence > checkpoint.treeSize()) {
            throw new IllegalArgumentException("체크포인트 범위 밖의 sequence입니다.");
        }
        List<SignedAuditEvent> events = ledger.snapshot();
        if (events.size() < checkpoint.treeSize()) {
            throw new IllegalStateException("원장이 체크포인트보다 짧습니다. 꼬리 절단이 의심됩니다.");
        }
        List<String> hashes = eventHashes(events, (int) checkpoint.treeSize());
        int index = (int) (sequence - 1);
        return new InclusionProof(
                checkpoint.checkpointId(), sequence, index, checkpoint.treeSize(),
                hashes.get(index), merkleTreeService.auditPath(hashes, index),
                checkpoint.merkleRoot());
    }

    /* 제3자는 원장 없이 증명과 체크포인트 root만으로 포함 여부를 확인할 수 있다. */
    public boolean verifyProof(InclusionProof proof) {
        return merkleTreeService.verifyInclusion(
                proof.leafEventHash(), proof.leafIndex(), proof.treeSize(),
                proof.auditPath(), proof.merkleRoot());
    }

    /* 해시 체인, 체크포인트 서명, 꼬리 절단, 재작성, 앵커 상태를 모두 점검한다. */
    public synchronized LedgerVerificationReport verify() {
        List<String> failures = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        boolean chainValid = ledger.verifyAll();
        if (!chainValid) failures.add("해시 체인 또는 이벤트 서명 검증에 실패했습니다.");

        List<SignedAuditEvent> events = ledger.snapshot();
        for (SignedCheckpoint checkpoint : checkpoints) {
            String label = "체크포인트 " + checkpoint.checkpointId();
            if (!signatureValid(checkpoint)) {
                failures.add(label + ": 서명이 올바르지 않습니다.");
                continue;
            }
            if (checkpoint.treeSize() > events.size()) {
                failures.add(label + ": 원장이 체크포인트보다 짧습니다. 꼬리 절단이 의심됩니다.");
                continue;
            }
            int size = (int) checkpoint.treeSize();
            String recomputed = merkleTreeService.rfc6962Root(eventHashes(events, size));
            if (!recomputed.equals(checkpoint.merkleRoot())
                    || !events.get(size - 1).eventHash().equals(checkpoint.headEventHash())) {
                failures.add(label + ": 고정된 구간이 재작성되었습니다.");
            }
            String receipt = checkpoint.anchorReceipt();
            if (receipt == null || receipt.isBlank()
                    || receipt.startsWith("ANCHOR_DISABLED") || receipt.startsWith("OTS_FAILED")) {
                warnings.add(label + ": 외부 앵커가 없습니다. 로컬 서명만으로는 전체 재작성을 막지 못합니다.");
            }
        }
        if (!events.isEmpty()
                && (checkpoints.isEmpty() || checkpoints.getLast().treeSize() < events.size())) {
            warnings.add("마지막 체크포인트 이후의 이벤트는 아직 고정되지 않았습니다.");
        }
        return new LedgerVerificationReport(
                failures.isEmpty(), chainValid, checkpoints.size(),
                List.copyOf(failures), List.copyOf(warnings));
    }

    private boolean signatureValid(SignedCheckpoint checkpoint) {
        try {
            byte[] message = canonical(
                    checkpoint.checkpointId(), checkpoint.treeSize(), checkpoint.merkleRoot(),
                    checkpoint.headEventHash(), checkpoint.createdAt(), checkpoint.gatewayDid());
            return integrityVerifier.verify(
                    didKeyService.resolvePublicKey(checkpoint.gatewayDid()), message,
                    Base64.getUrlDecoder().decode(checkpoint.signature()));
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private List<String> eventHashes(List<SignedAuditEvent> events, int size) {
        return events.subList(0, size).stream().map(SignedAuditEvent::eventHash).toList();
    }

    private byte[] canonical(
            String checkpointId, long treeSize, String root, String head,
            Instant createdAt, String gatewayDid) {
        return String.join("\n", "CHECKPOINT-V1", checkpointId, Long.toString(treeSize),
                root, head, createdAt.toString(), gatewayDid).getBytes(StandardCharsets.UTF_8);
    }

    private String sign(byte[] message) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyProvider.keyPair().getPrivate());
            signer.update(message);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        } catch (Exception exception) {
            throw new IllegalStateException("체크포인트 서명에 실패했습니다.", exception);
        }
    }
}
