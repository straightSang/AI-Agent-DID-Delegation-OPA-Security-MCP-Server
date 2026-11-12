package io.github.straightsang.agentsecurity.mcp.demo;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

/* Signs the server-issued challenge string with the Agent's Ed25519 private key. */
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

        // Sign the challenge value from the response, not the challengeId.
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(args[0].getBytes(StandardCharsets.UTF_8));

        String encodedSignature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signer.sign());

        System.out.println("challengeSignature:");
        System.out.println(encodedSignature);
    }
}

