package io.github.straightsang.agentsecurity.mcp.audit;

import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/*
 * 이전 이벤트 해시를 연결하고 각 이벤트를 Gateway Ed25519 키로 서명한다.
 * security.audit.ledger-path를 지정하면 이벤트를 한 줄씩 파일에 덧붙여 재시작 후에도 이어 쓰며,
 * 시작할 때 저장된 체인과 서명을 전부 다시 검증한다. 검증에 실패하면 서버를 시작하지 않는다(fail-closed).
 */
@Service
public class SignedAuditLedger {
    private static final String GENESIS_HASH = "0".repeat(64);

    private final List<SignedAuditEvent> events = new ArrayList<>();
    private final AuditEventCanonicalizer canonicalizer;
    private final GatewaySigningKeyProvider keyProvider;
    private final DidKeyService didKeyService;
    private final CommandIntegrityVerifier integrityVerifier;
    private final Path storagePath;

    public SignedAuditLedger(
            AuditEventCanonicalizer canonicalizer,
            GatewaySigningKeyProvider keyProvider,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier) {
        this(canonicalizer, keyProvider, didKeyService, integrityVerifier, "");
    }

    @Autowired
    public SignedAuditLedger(
            AuditEventCanonicalizer canonicalizer,
            GatewaySigningKeyProvider keyProvider,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier,
            @Value("${security.audit.ledger-path:}") String ledgerPath) {
        this.canonicalizer = canonicalizer;
        this.keyProvider = keyProvider;
        this.didKeyService = didKeyService;
        this.integrityVerifier = integrityVerifier;
        this.storagePath = ledgerPath == null || ledgerPath.isBlank()
                ? null : Path.of(ledgerPath).toAbsolutePath().normalize();
        loadStoredEvents();
    }

    public synchronized SignedAuditEvent append(
            String requestId,
            String actorDid,
            String action,
            String resource,
            String decision,
            String reason,
            String requestHash,
            String responseHash) {
        long sequence = events.size() + 1L;
        String previousHash = events.isEmpty()
                ? GENESIS_HASH
                : events.getLast().eventHash();
        SignedAuditEvent unsigned = new SignedAuditEvent(
                sequence, Instant.now(), requestId, actorDid, action, resource,
                decision, reason, requestHash, responseHash, previousHash,
                null, null, null);
        try {
            byte[] canonical = canonicalizer.canonicalize(unsigned);
            String eventHash = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(canonical));
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyProvider.keyPair().getPrivate());
            signer.update(HexFormat.of().parseHex(eventHash));
            String signature = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signer.sign());
            SignedAuditEvent signed = unsigned.withProof(
                    eventHash, keyProvider.gatewayDid(), signature);
            persist(signed);
            events.add(signed);
            return signed;
        } catch (Exception exception) {
            throw new IllegalStateException("감사 이벤트 서명 또는 저장에 실패했습니다.", exception);
        }
    }

    public synchronized List<SignedAuditEvent> snapshot() {
        return List.copyOf(events);
    }

    public synchronized boolean verifyAll() {
        String expectedPrevious = GENESIS_HASH;
        for (SignedAuditEvent event : events) {
            try {
                if (!event.previousEventHash().equals(expectedPrevious)) return false;
                String calculated = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(canonicalizer.canonicalize(event)));
                if (!calculated.equals(event.eventHash())) return false;
                boolean signatureValid = integrityVerifier.verify(
                        didKeyService.resolvePublicKey(event.gatewayDid()),
                        HexFormat.of().parseHex(event.eventHash()),
                        Base64.getUrlDecoder().decode(event.signature()));
                if (!signatureValid) return false;
                expectedPrevious = event.eventHash();
            } catch (RuntimeException | java.security.NoSuchAlgorithmException exception) {
                return false;
            }
        }
        return true;
    }

    /* 이벤트를 파일에 한 줄로 덧붙인다. 쓰기에 실패하면 메모리에도 추가하지 않는다. */
    private void persist(SignedAuditEvent event) throws IOException {
        if (storagePath == null) return;
        Path parent = storagePath.getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.write(storagePath, (encodeLine(event) + "\n").getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.SYNC);
    }

    private void loadStoredEvents() {
        if (storagePath == null || !Files.exists(storagePath)) return;
        try {
            for (String line : Files.readAllLines(storagePath, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) events.add(decodeLine(line));
            }
        } catch (IOException | RuntimeException exception) {
            throw new IllegalStateException("저장된 감사 원장을 읽지 못했습니다: " + storagePath, exception);
        }
        if (!verifyAll()) {
            throw new IllegalStateException("저장된 감사 원장의 해시 체인 또는 서명 검증에 실패했습니다: " + storagePath);
        }
    }

    private String encodeLine(SignedAuditEvent event) {
        return String.join("\t",
                Long.toString(event.sequence()), event.timestamp().toString(),
                b64(event.requestId()), b64(event.actorDid()), b64(event.action()),
                b64(event.resource()), b64(event.decision()), b64(event.reason()),
                b64(event.requestHash()), b64(event.responseHash()),
                b64(event.previousEventHash()), b64(event.eventHash()),
                b64(event.gatewayDid()), b64(event.signature()));
    }

    private SignedAuditEvent decodeLine(String line) {
        String[] parts = line.split("\t", -1);
        if (parts.length != 14) throw new IllegalArgumentException("원장 줄 형식이 올바르지 않습니다.");
        return new SignedAuditEvent(
                Long.parseLong(parts[0]), Instant.parse(parts[1]),
                unb64(parts[2]), unb64(parts[3]), unb64(parts[4]), unb64(parts[5]),
                unb64(parts[6]), unb64(parts[7]), unb64(parts[8]), unb64(parts[9]),
                unb64(parts[10]), unb64(parts[11]), unb64(parts[12]), unb64(parts[13]));
    }

    private String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
    }

    private String unb64(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }
}
