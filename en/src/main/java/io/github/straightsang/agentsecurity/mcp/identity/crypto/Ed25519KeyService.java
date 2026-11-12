package io.github.straightsang.agentsecurity.mcp.identity.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Service;

/** Ed25519 key-pair generator for labs and tests; production keys belong in an Agent-side KMS or HSM. */
@Service
public class Ed25519KeyService {
    public KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("현재 Java 환경에서 Ed25519를 사용할 수 없습니다.", exception);
        }
    }
}
