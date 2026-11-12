package io.github.straightsang.agentsecurity.mcp.demo;

import io.github.straightsang.agentsecurity.mcp.delegation.DelegationTokenCanonicalizer;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

/* 사용자가 Agent에게 calculator_add 권한을 주는 최초 root 위임 토큰을 만든다. */
public final class DelegationTokenCli {
    private DelegationTokenCli() {
    }

    public static void main(String[] args) throws Exception {
        Path secretsDirectory = LocalIdentitySetupCli.secretsDirectory();
        String userDid = LocalIdentitySetupCli.readText(secretsDirectory.resolve("user.did"));
        String agentDid = LocalIdentitySetupCli.readText(secretsDirectory.resolve("agent.did"));
        PrivateKey userPrivateKey = LocalIdentitySetupCli.loadPrivateKey(
                secretsDirectory.resolve("user-private.pkcs8.b64"));

        Instant issuedAt = Instant.now();
        DelegationToken unsignedToken = new DelegationToken(
                UUID.randomUUID().toString(),
                null,
                userDid,
                agentDid,
                "agent-security-mcp",
                Set.of("calculator_add"),
                Set.of("calculator"),
                issuedAt,
                issuedAt.plusSeconds(15 * 60),
                0,
                null);

        // 서버와 같은 정규화 결과에 서명해야 검증 시 바이트가 일치한다.
        DelegationTokenCanonicalizer canonicalizer = new DelegationTokenCanonicalizer();
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(userPrivateKey);
        signer.update(canonicalizer.canonicalize(unsignedToken));

        String signature = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signer.sign());
        DelegationToken signedToken = unsignedToken.withSignature(signature);
        String json = toJson(signedToken);

        Path outputPath = secretsDirectory.resolve("root-delegation-token.json");
        Files.writeString(
                outputPath,
                json,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);

        System.out.println("root 위임 토큰 생성 완료: " + outputPath);
        System.out.println(json);
    }

    private static String toJson(DelegationToken token) {
        return """
                {
                  "tokenId": "%s",
                  "parentTokenId": null,
                  "issuer": "%s",
                  "subject": "%s",
                  "audience": "%s",
                  "actions": ["calculator_add"],
                  "resources": ["calculator"],
                  "issuedAt": "%s",
                  "expiresAt": "%s",
                  "delegationDepth": %d,
                  "signature": "%s"
                }
                """.formatted(
                token.tokenId(),
                token.issuer(),
                token.subject(),
                token.audience(),
                token.issuedAt(),
                token.expiresAt(),
                token.delegationDepth(),
                token.signature());
    }
}

