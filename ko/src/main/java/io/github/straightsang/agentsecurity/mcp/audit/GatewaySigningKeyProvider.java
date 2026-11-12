package io.github.straightsang.agentsecurity.mcp.audit;

import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import java.security.KeyPair;
import org.springframework.stereotype.Component;

/* 로컬 실습용 Gateway 서명 키다. 운영 환경에서는 AWS KMS/HSM 구현으로 교체한다. */
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
