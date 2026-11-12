package io.github.straightsang.agentsecurity.mcp.identity.did;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import org.junit.jupiter.api.Test;

class DidKeyServiceTest {
    private final DidKeyService service = new DidKeyService();

    @Test
    void convertsEd25519PublicKeyToDidAndBack() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String did = service.createDid(pair.getPublic());
        PublicKey restored = service.resolvePublicKey(did);
        assertThat(did).startsWith("did:key:z");
        assertThat(restored.getEncoded()).isEqualTo(pair.getPublic().getEncoded());
    }
}
