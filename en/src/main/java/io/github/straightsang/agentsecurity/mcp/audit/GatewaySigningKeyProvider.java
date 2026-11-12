package io.github.straightsang.agentsecurity.mcp.audit;

import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import java.security.KeyPair;
import org.springframework.stereotype.Component;

/* Local lab Gateway signing key; replace it with AWS KMS or an HSM in production. */
@Component
public class GatewaySigningKeyProvider {
    private final KeyPair keyPair;
    private final String gatewayDid;

    public GatewaySigningKeyProvider(
            Ed25519KeyService keyService,
            DidKeyService didKeyService) {
        this.keyPair = keyService.generateKeyPair();
        this.gatewayDid = didKeyService.createDid(keyPair.getPublic());
    }

    public KeyPair keyPair() {
        return keyPair;
    }

    public String gatewayDid() {
        return gatewayDid;
    }
}
