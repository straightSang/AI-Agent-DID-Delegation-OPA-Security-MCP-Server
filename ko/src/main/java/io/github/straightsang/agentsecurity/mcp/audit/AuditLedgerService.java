package io.github.straightsang.agentsecurity.mcp.audit;

import io.github.straightsang.agentsecurity.mcp.crypto.SigningService;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

/** 인스턴스별 서명 해시 체인을 만들고 주기적으로 Merkle root를 외부 앵커에 고정한다. */
@Service
public class AuditLedgerService {
    private static final String GENESIS = "0".repeat(64);
    private final List<AuditLedgerEntry> entries = new ArrayList<>();
    private final String instanceId;
    private final SigningService signingService;
    private final MerkleTreeService merkleTreeService;
    private final LedgerAnchorService anchorService;
    private final AuditEventSink eventSink;

    public AuditLedgerService(
            SigningService signingService,
            MerkleTreeService merkleTreeService,
            LedgerAnchorService anchorService,
            AuditEventSink eventSink) {
        this.signingService = signingService;
        this.merkleTreeService = merkleTreeService;
        this.anchorService = anchorService;
        this.eventSink = eventSink;
        this.instanceId = resolveInstanceId();
    }

    public synchronized AuditLedgerEntry append(
            String requestHash, String responseHash, String actorDid,
            String action, String resource, String decision) {
        long sequence = entries.size() + 1L;
        String previous = entries.isEmpty() ? GENESIS : entries.getLast().eventHash();
        Instant timestamp = Instant.now();
        String canonical = String.join("\n", instanceId, Long.toString(sequence), previous,
                requestHash, responseHash, actorDid, action, resource, decision, timestamp.toString());
        String eventHash = sha256(canonical);
        String signature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signingService.sign(eventHash.getBytes(StandardCharsets.UTF_8)));
        AuditLedgerEntry entry = new AuditLedgerEntry(
                instanceId, sequence, previous, requestHash, responseHash, actorDid,
                action, resource, decision, timestamp, eventHash,
                signingService.algorithm(), signature);
        entries.add(entry);
        eventSink.store(entry);
        return entry;
    }

    public synchronized LedgerCheckpoint checkpoint() {
        if (entries.isEmpty()) throw new IllegalStateException("체크포인트를 만들 원장 항목이 없습니다.");
        String root = merkleTreeService.root(entries.stream().map(AuditLedgerEntry::eventHash).toList());
        Instant now = Instant.now();
        String checkpointId = UUID.randomUUID().toString();
        String canonical = String.join("\n", checkpointId, instanceId, "1",
                Long.toString(entries.size()), root, now.toString());
        String signature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signingService.sign(canonical.getBytes(StandardCharsets.UTF_8)));
        LedgerCheckpoint unsignedReceipt = new LedgerCheckpoint(
                checkpointId, instanceId, 1, entries.size(), root, now,
                signingService.algorithm(), signature, null);
        return unsignedReceipt.withReceipt(anchorService.anchor(unsignedReceipt));
    }

    public synchronized List<AuditLedgerEntry> entries() {
        return List.copyOf(entries);
    }

    /** 이전 해시, 재계산한 이벤트 해시, 서버 서명을 모두 다시 확인한다. */
    public synchronized boolean verifyChain() {
        String expectedPrevious = GENESIS;
        for (AuditLedgerEntry entry : entries) {
            String canonical = String.join("\n", entry.instanceId(), Long.toString(entry.sequence()),
                    entry.previousHash(), entry.requestHash(), entry.responseHash(), entry.actorDid(),
                    entry.action(), entry.resource(), entry.decision(), entry.timestamp().toString());
            if (!expectedPrevious.equals(entry.previousHash()) || !sha256(canonical).equals(entry.eventHash())) {
                return false;
            }
            byte[] signature;
            try {
                signature = Base64.getUrlDecoder().decode(entry.signature());
            } catch (IllegalArgumentException exception) {
                return false;
            }
            if (!signingService.algorithm().equals(entry.signatureAlgorithm())
                    || !signingService.verify(
                            entry.eventHash().getBytes(StandardCharsets.UTF_8), signature)) {
                return false;
            }
            expectedPrevious = entry.eventHash();
        }
        return true;
    }

    private String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256을 사용할 수 없습니다.", exception);
        }
    }

    private String resolveInstanceId() {
        try {
            return InetAddress.getLocalHost().getHostName() + "-" + UUID.randomUUID();
        } catch (Exception exception) {
            return "instance-" + UUID.randomUUID();
        }
    }
}
