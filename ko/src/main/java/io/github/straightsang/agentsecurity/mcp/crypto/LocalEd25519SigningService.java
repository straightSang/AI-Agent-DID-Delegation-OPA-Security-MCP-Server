package io.github.straightsang.agentsecurity.mcp.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** 로컬 실습용 임시 키다. 서버 재시작 시 바뀌므로 운영에서는 KMS 구현을 사용한다. */
@Component
@Profile("!aws")
public class LocalEd25519SigningService implements SigningService {
    private final KeyPair keyPair;

    public LocalEd25519SigningService() {
        try {
            keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("로컬 서명 키를 만들지 못했습니다.", exception);
        }
    }

    @Override public String algorithm() { return "Ed25519"; }

    @Override
    public byte[] sign(byte[] message) {
        try {
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(message);
            return signer.sign();
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("서명에 실패했습니다.", exception);
        }
    }

    @Override
    public boolean verify(byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException exception) {
            return false;
        }
    }
}
