package io.github.straightsang.agentsecurity.mcp.crypto;

import io.github.straightsang.agentsecurity.mcp.state.AwsStateProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.VerifyRequest;

/** 운영에서는 KMS 비대칭 P-256 키가 개인키를 외부로 내보내지 않은 채 서명한다. */
@Component
@Profile("aws")
public class KmsSigningService implements SigningService {
    private final KmsClient kms;
    private final String keyId;

    public KmsSigningService(KmsClient kms, AwsStateProperties properties) {
        this.kms = kms;
        this.keyId = properties.kmsKeyId();
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalStateException("security.aws.kms-key-id 설정이 필요합니다.");
        }
    }

    @Override public String algorithm() { return SigningAlgorithmSpec.ECDSA_SHA_256.toString(); }

    @Override
    public byte[] sign(byte[] message) {
        return kms.sign(SignRequest.builder()
                        .keyId(keyId).message(SdkBytes.fromByteArray(message))
                        .messageType(MessageType.RAW)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256).build())
                .signature().asByteArray();
    }

    @Override
    public boolean verify(byte[] message, byte[] signature) {
        return kms.verify(VerifyRequest.builder()
                        .keyId(keyId).message(SdkBytes.fromByteArray(message))
                        .signature(SdkBytes.fromByteArray(signature))
                        .messageType(MessageType.RAW)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256).build())
                .signatureValid();
    }
}
