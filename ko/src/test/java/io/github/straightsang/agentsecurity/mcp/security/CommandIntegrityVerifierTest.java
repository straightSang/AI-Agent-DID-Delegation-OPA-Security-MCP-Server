package io.github.straightsang.agentsecurity.mcp.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.straightsang.agentsecurity.mcp.exception.CommandIntegrityVerificationException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.junit.jupiter.api.Test;

class CommandIntegrityVerifierTest {
    private final CommandIntegrityVerifier verifier = new CommandIntegrityVerifier();

    @Test
    void acceptsValidSignature() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        byte[] command = bytes("{\"action\":\"read\"}");
        byte[] signature = sign(keyPair, command);
        assertThat(verifier.verify(keyPair.getPublic(), command, signature)).isTrue();
    }

    @Test
    void rejectsTamperedCommand() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        byte[] signature = sign(keyPair, bytes("{\"action\":\"read\"}"));
        assertThat(verifier.verify(
                keyPair.getPublic(), bytes("{\"action\":\"write\"}"), signature)).isFalse();
    }

    @Test
    void rejectsSignatureCreatedByDifferentKey() throws Exception {
        KeyPair trusted = generateEd25519KeyPair();
        KeyPair attacker = generateEd25519KeyPair();
        byte[] command = bytes("{\"action\":\"read\"}");
        assertThat(verifier.verify(
                trusted.getPublic(), command, sign(attacker, command))).isFalse();
    }

    @Test
    void rejectsMissingInputs() throws Exception {
        KeyPair keyPair = generateEd25519KeyPair();
        byte[] command = bytes("{\"action\":\"read\"}");
        byte[] signature = sign(keyPair, command);

        assertThatThrownBy(() -> verifier.verify(null, command, signature))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> verifier.verify(keyPair.getPublic(), null, signature))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> verifier.verify(keyPair.getPublic(), command, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsUnsupportedPublicKeyType() throws Exception {
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(2048);
        KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
        assertThatThrownBy(() -> verifier.verify(
                rsaKeyPair.getPublic(), bytes("test"), new byte[] {1, 2, 3}))
                .isInstanceOf(CommandIntegrityVerificationException.class);
    }

    private KeyPair generateEd25519KeyPair() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private byte[] sign(KeyPair keyPair, byte[] command) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keyPair.getPrivate());
        signer.update(command);
        return signer.sign();
    }

    private byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
