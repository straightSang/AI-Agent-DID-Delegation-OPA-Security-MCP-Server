package io.github.straightsang.agentsecurity.mcp.security;

import io.github.straightsang.agentsecurity.mcp.exception.CommandIntegrityVerificationException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import org.springframework.stereotype.Component;

/** Uses an Ed25519 public key to verify that a signed command was not modified. */
@Component
public class CommandIntegrityVerifier {
    private static final String SIGNATURE_ALGORITHM = "Ed25519";

    public boolean verify(PublicKey publicKey, byte[] commandBytes, byte[] signatureBytes) {
        validateInput(publicKey, commandBytes, signatureBytes);
        Signature verifier = createVerifier();
        try {
            verifier.initVerify(publicKey);
            verifier.update(commandBytes);
            return verifier.verify(signatureBytes);
        } catch (InvalidKeyException exception) {
            throw new CommandIntegrityVerificationException(
                    "Ed25519 서명 검증에 사용할 수 없는 공개키입니다.", exception);
        } catch (SignatureException exception) {
            throw new CommandIntegrityVerificationException(
                    "전자서명 데이터를 처리하지 못했습니다.", exception);
        }
    }

    private Signature createVerifier() {
        try {
            return Signature.getInstance(SIGNATURE_ALGORITHM);
        } catch (NoSuchAlgorithmException exception) {
            throw new CommandIntegrityVerificationException(
                    "현재 Java 실행 환경에서 Ed25519 알고리즘을 사용할 수 없습니다.", exception);
        }
    }

    private void validateInput(PublicKey publicKey, byte[] commandBytes, byte[] signatureBytes) {
        if (publicKey == null) {
            throw new IllegalArgumentException("전자서명을 검증할 공개키가 없습니다.");
        }
        if (commandBytes == null || commandBytes.length == 0) {
            throw new IllegalArgumentException("검증할 명령 데이터가 없습니다.");
        }
        if (signatureBytes == null || signatureBytes.length == 0) {
            throw new IllegalArgumentException("검증할 전자서명이 없습니다.");
        }
    }
}
