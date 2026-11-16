package io.github.straightsang.agentsecurity.mcp.audit;

import io.github.straightsang.agentsecurity.mcp.identity.crypto.Ed25519KeyService;
import io.github.straightsang.agentsecurity.mcp.identity.did.DidKeyService;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/*
 * Gateway 서명 키를 제공한다.
 * security.audit.gateway-key-path가 비어 있으면 실행할 때마다 새 임시 키를 만든다(재시작 후 DID가 바뀐다).
 * 경로가 있으면 그 파일의 키를 쓰고, 파일이 없으면 새로 만들어 저장한다. 파일 권한은 가능한 환경에서 600으로 제한한다.
 * 운영 환경에서는 파일 대신 KMS/HSM 구현으로 교체한다.
 */
@Component
public class GatewaySigningKeyProvider {
    private static final String PRIVATE_PREFIX = "PKCS8:";
    private static final String PUBLIC_PREFIX = "X509:";

    private final KeyPair keyPair;
    private final String gatewayDid;

    public GatewaySigningKeyProvider(
            Ed25519KeyService keyService,
            DidKeyService didKeyService) {
        this(keyService, didKeyService, null);
    }

    @Autowired
    public GatewaySigningKeyProvider(
            Ed25519KeyService keyService,
            DidKeyService didKeyService,
            @Value("${security.audit.gateway-key-path:}") String keyPath) {
        this.keyPair = keyPath == null || keyPath.isBlank()
                ? keyService.generateKeyPair()
                : loadOrCreate(Path.of(keyPath), keyService);
        this.gatewayDid = didKeyService.createDid(keyPair.getPublic());
    }

    public KeyPair keyPair() {
        return keyPair;
    }

    public String gatewayDid() {
        return gatewayDid;
    }

    private KeyPair loadOrCreate(Path path, Ed25519KeyService keyService) {
        try {
            if (Files.exists(path)) {
                return load(path);
            }
            KeyPair created = keyService.generateKeyPair();
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            String content = PRIVATE_PREFIX + encode(created.getPrivate().getEncoded()) + "\n"
                    + PUBLIC_PREFIX + encode(created.getPublic().getEncoded()) + "\n";
            Files.writeString(path, content, StandardOpenOption.CREATE_NEW);
            restrictPermissions(path);
            return created;
        } catch (IOException | GeneralSecurityException exception) {
            throw new IllegalStateException("Gateway 서명 키를 준비하지 못했습니다.", exception);
        }
    }

    private KeyPair load(Path path) throws IOException, GeneralSecurityException {
        List<String> lines = Files.readAllLines(path);
        String privateLine = lines.stream().filter(line -> line.startsWith(PRIVATE_PREFIX))
                .findFirst().orElseThrow(() -> new IllegalStateException("Gateway 개인키 줄이 없습니다."));
        String publicLine = lines.stream().filter(line -> line.startsWith(PUBLIC_PREFIX))
                .findFirst().orElseThrow(() -> new IllegalStateException("Gateway 공개키 줄이 없습니다."));
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(
                Base64.getUrlDecoder().decode(privateLine.substring(PRIVATE_PREFIX.length()).trim())));
        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(
                Base64.getUrlDecoder().decode(publicLine.substring(PUBLIC_PREFIX.length()).trim())));
        requireMatchingPair(privateKey, publicKey);
        return new KeyPair(publicKey, privateKey);
    }

    /* 개인키와 공개키가 서로 짝이 맞는지 서명해서 확인한다. */
    private void requireMatchingPair(PrivateKey privateKey, PublicKey publicKey)
            throws GeneralSecurityException {
        byte[] probe = "gateway-key-self-test".getBytes();
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(probe);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(probe);
        if (!verifier.verify(signature)) {
            throw new IllegalStateException("저장된 Gateway 개인키와 공개키가 서로 맞지 않습니다.");
        }
    }

    private void restrictPermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException exception) {
            // Windows처럼 POSIX 권한이 없는 환경에서는 OS 사용자 권한에 맡긴다.
        }
    }

    private String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
