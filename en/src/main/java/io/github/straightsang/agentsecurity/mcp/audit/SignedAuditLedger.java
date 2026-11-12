package io.github.straightsang.agentsecurity.mcp.audit;

import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.springframework.stereotype.Service;

/* Links the previous-event hash and signs every event with the Gateway Ed25519 key. */
@Service
public class SignedAuditLedger {
    private static final String GENESIS_HASH = "0".repeat(64);

    private final List<SignedAuditEvent> events = new ArrayList<>();
    private final AuditEventCanonicalizer canonicalizer;
    private final GatewaySigningKeyProvider keyProvider;
    private final DidKeyService didKeyService;
    private final CommandIntegrityVerifier integrityVerifier;

    public SignedAuditLedger(
            AuditEventCanonicalizer canonicalizer,
            GatewaySigningKeyProvider keyProvider,
            DidKeyService didKeyService,
            CommandIntegrityVerifier integrityVerifier) {
        this.canonicalizer = canonicalizer;
        this.keyProvider = keyProvider;
        this.didKeyService = didKeyService;
        this.integrityVerifier = integrityVerifier;
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
            events.add(signed);
            return signed;
        } catch (Exception exception) {
            throw new IllegalStateException("감사 이벤트 서명에 실패했습니다.", exception);
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
}
