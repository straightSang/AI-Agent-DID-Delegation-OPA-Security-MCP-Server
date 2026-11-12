package io.github.straightsang.agentsecurity.mcp.demo;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

/* 서버가 발급한 challenge 문자열을 Agent 개인키로 Ed25519 서명한다. */
public final class ChallengeSignerCli {
    private ChallengeSignerCli() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1 || args[0].isBlank()) {
            System.out.println("사용법: ChallengeSignerCli <challenge 값>");
            System.exit(1);
        }

        Path privateKeyPath = LocalIdentitySetupCli.secretsDirectory()
                .resolve("agent-private.pkcs8.b64");
        PrivateKey privateKey = LocalIdentitySetupCli.loadPrivateKey(privateKeyPath);

        // challengeId가 아니라 서버 응답의 challenge 문자열 자체를 서명한다.
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(args[0].getBytes(StandardCharsets.UTF_8));

        String encodedSignature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signer.sign());

        System.out.println("challengeSignature:");
        System.out.println(encodedSignature);
    }
}

