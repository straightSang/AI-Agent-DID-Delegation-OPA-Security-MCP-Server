package io.github.straightsang.agentsecurity.mcp.testsupport;

import io.github.straightsang.agentsecurity.mcp.audit.AuditEventCanonicalizer;
import io.github.straightsang.agentsecurity.mcp.audit.GatewaySigningKeyProvider;
import io.github.straightsang.agentsecurity.mcp.audit.SignedAuditLedger;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationSignatureVerifier;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationTokenCanonicalizer;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationTokenService;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationProperties;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationRevocationService;
import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import io.github.straightsang.agentsecurity.mcp.security.CommandIntegrityVerifier;
import io.github.straightsang.agentsecurity.mcp.security.DelegationVerifier;
import io.github.straightsang.agentsecurity.mcp.state.InMemorySecurityStateStore;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Base64;
import java.util.Set;

/* 테스트에서 공통으로 쓰는 키, DID, 원장, 위임 도구 묶음이다. */
public class Fixtures {
    public final Ed25519KeyService keyService = new Ed25519KeyService();
    public final DidKeyService didKeyService = new DidKeyService();
    public final CommandIntegrityVerifier integrityVerifier = new CommandIntegrityVerifier();
    public final InMemorySecurityStateStore stateStore = new InMemorySecurityStateStore();
    public final DelegationTokenCanonicalizer canonicalizer = new DelegationTokenCanonicalizer();

    public final KeyPair userKeys = keyService.generateKeyPair();
    public final String userDid = didKeyService.createDid(userKeys.getPublic());

    public final DelegationProperties delegationProperties;
    public final DelegationRevocationService revocationService = new DelegationRevocationService(stateStore);
    public final DelegationVerifier delegationVerifier;
    public final DelegationTokenService tokenService;
    public final GatewaySigningKeyProvider gatewayKeys =
            new GatewaySigningKeyProvider(keyService, didKeyService);
    public final SignedAuditLedger ledger;

    public Fixtures() {
        delegationProperties = new DelegationProperties("agent-security-mcp", 3, Set.of(userDid));
        DelegationSignatureVerifier signatureVerifier = new DelegationSignatureVerifier(
                didKeyService, canonicalizer, integrityVerifier);
        delegationVerifier = new DelegationVerifier(signatureVerifier, revocationService, delegationProperties);
        tokenService = new DelegationTokenService(canonicalizer, delegationVerifier);
        ledger = new SignedAuditLedger(
                new AuditEventCanonicalizer(), gatewayKeys, didKeyService, integrityVerifier);
    }

    public KeyPair newKeys() {
        return keyService.generateKeyPair();
    }

    public String didOf(KeyPair keys) {
        return didKeyService.createDid(keys.getPublic());
    }

    public static String sign(KeyPair keys, byte[] message) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keys.getPrivate());
            signer.update(message);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    public static String sign(KeyPair keys, String message) {
        return sign(keys, message.getBytes(StandardCharsets.UTF_8));
    }

    public static Path tempDir() {
        try {
            return Files.createTempDirectory("agent-sec-test");
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
