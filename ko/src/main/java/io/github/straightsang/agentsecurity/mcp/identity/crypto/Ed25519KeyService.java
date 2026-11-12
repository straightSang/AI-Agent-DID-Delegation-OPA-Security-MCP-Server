package io.github.straightsang.agentsecurity.mcp.identity.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Service;

/** 학습·테스트용 Ed25519 키쌍 생성기다. 운영 개인키는 Agent 측 KMS/HSM에서 관리한다. */
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
