package io.github.straightsang.agentsecurity.mcp.demo;

import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Set;

/*
 * 로컬 학습용 사용자·Agent 신원 생성기다.
 * 개인키는 프로젝트의 .secrets 폴더에 저장하며 기존 키는 덮어쓰지 않는다.
 */
public final class LocalIdentitySetupCli {
    private static final Path PROJECT_ROOT = Path.of("").toAbsolutePath().normalize();
    private static final Path SECRETS_DIRECTORY = PROJECT_ROOT.resolve(".secrets");

    private LocalIdentitySetupCli() {
    }

    public static void main(String[] args) throws Exception {
        verifySecretsAreIgnoredByGit();
        Files.createDirectories(SECRETS_DIRECTORY);

        Ed25519KeyService keyService = new Ed25519KeyService();
        DidKeyService didKeyService = new DidKeyService();

        createIdentity("user", keyService, didKeyService);
        createIdentity("agent", keyService, didKeyService);

        System.out.println();
        System.out.println("신원 생성이 완료되었습니다.");
        System.out.println("키 저장 위치: " + SECRETS_DIRECTORY);
        System.out.println("사용자 DID: " + readText(SECRETS_DIRECTORY.resolve("user.did")));
        System.out.println("Agent DID: " + readText(SECRETS_DIRECTORY.resolve("agent.did")));
    }

    private static void createIdentity(
            String name,
            Ed25519KeyService keyService,
            DidKeyService didKeyService) throws Exception {
        Path privateKeyPath = SECRETS_DIRECTORY.resolve(name + "-private.pkcs8.b64");
        Path publicKeyPath = SECRETS_DIRECTORY.resolve(name + "-public.x509.b64");
        Path didPath = SECRETS_DIRECTORY.resolve(name + ".did");

        // 기존 키를 덮어쓰면 DID와 기존 서명을 복구할 수 없으므로 실행을 중단한다.
        refuseOverwrite(privateKeyPath);
        refuseOverwrite(publicKeyPath);
        refuseOverwrite(didPath);

        KeyPair keyPair = keyService.generateKeyPair();
        String privateKeyBase64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyBase64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(keyPair.getPublic().getEncoded());
        String did = didKeyService.createDid(keyPair.getPublic());

        writeNewFile(privateKeyPath, privateKeyBase64);
        writeNewFile(publicKeyPath, publicKeyBase64);
        writeNewFile(didPath, did);
        restrictPrivateKeyPermissions(privateKeyPath);

        System.out.println(name + " DID 생성 완료: " + did);
    }

    /* PKCS#8로 저장한 Ed25519 개인키를 Challenge/위임 CLI에서 다시 읽는다. */
    static PrivateKey loadPrivateKey(Path privateKeyPath) throws Exception {
        byte[] keyBytes = Base64.getUrlDecoder().decode(readText(privateKeyPath));
        return KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    static String readText(Path path) throws Exception {
        return Files.readString(path, StandardCharsets.UTF_8).trim();
    }

    static Path secretsDirectory() {
        return SECRETS_DIRECTORY;
    }

    private static void verifySecretsAreIgnoredByGit() throws Exception {
        Path gitignore = PROJECT_ROOT.resolve(".gitignore");
        if (!Files.exists(gitignore)) {
            throw new IllegalStateException(".gitignore 파일이 없습니다.");
        }

        boolean ignored = Files.readAllLines(gitignore, StandardCharsets.UTF_8).stream()
                .map(String::trim)
                .anyMatch(line -> line.equals(".secrets/") || line.equals(".secrets"));
        if (!ignored) {
            throw new IllegalStateException(".gitignore에 .secrets/를 먼저 추가해야 합니다.");
        }
    }

    private static void refuseOverwrite(Path path) {
        if (Files.exists(path)) {
            throw new IllegalStateException("기존 신원 파일을 덮어쓰지 않습니다: " + path);
        }
    }

    private static void writeNewFile(Path path, String value) throws Exception {
        Files.writeString(
                path,
                value + System.lineSeparator(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW);
    }

    private static void restrictPrivateKeyPermissions(Path path) throws Exception {
        try {
            Files.setPosixFilePermissions(
                    path,
                    Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException exception) {
            // Windows/NTFS에서는 POSIX 권한을 지원하지 않을 수 있다.
            System.out.println("POSIX 파일 권한 설정을 지원하지 않습니다: " + path);
        }
    }
}

