package io.github.straightsang.agentsecurity.mcp.identity.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class Ed25519KeyServiceTest {
    @Test
    void createsEd25519KeyPair() {
        KeyPair keyPair = new Ed25519KeyService().generateKeyPair();
        assertThat(keyPair.getPrivate().getAlgorithm()).isEqualTo("EdDSA");
        assertThat(keyPair.getPublic().getAlgorithm()).isEqualTo("EdDSA");
    }
}
