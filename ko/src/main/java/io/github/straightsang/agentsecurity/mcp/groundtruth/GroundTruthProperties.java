package io.github.straightsang.agentsecurity.mcp.groundtruth;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/*
 * Ground Truth(권한 그래프, 도구 계보) 설정.
 * maxDepth/maxTokenTtl/maxFanOut: 이 값을 넘는 위임은 이상 징후로 본다.
 * sensitiveKeywords: 이 단어가 들어간 resource를 위임하면 SENSITIVE_SCOPE로 표시한다.
 * toolPinFile: 도구 설명 해시를 고정해 두는 파일. 설명이 바뀌면(rug pull) 격리한다.
 * pinCodeDigest: true면 도구 코드 해시가 바뀌어도 격리한다. 배포마다 바뀌므로 기본은 false다.
 * enforce: true면 앙상블이 BLOCK을 내린 요청을 실제로 거부한다. false면 기록만 한다.
 * trustedPublishers: 도구 게시자 신뢰 목록. 내장 도구의 게시자는 "local"이다.
 */
@ConfigurationProperties(prefix = "security.ground-truth")
public record GroundTruthProperties(
        Integer maxDepth,
        Duration maxTokenTtl,
        Integer maxFanOut,
        List<String> sensitiveKeywords,
        String toolPinFile,
        Boolean pinCodeDigest,
        Boolean enforce,
        List<String> trustedPublishers) {
    public GroundTruthProperties {
        maxDepth = maxDepth == null || maxDepth < 1 ? 3 : maxDepth;
        maxTokenTtl = maxTokenTtl == null ? Duration.ofHours(24) : maxTokenTtl;
        maxFanOut = maxFanOut == null || maxFanOut < 1 ? 10 : maxFanOut;
        sensitiveKeywords = sensitiveKeywords == null || sensitiveKeywords.isEmpty()
                ? List.of("secret", "private", "credential", "password", "personal")
                : List.copyOf(sensitiveKeywords);
        toolPinFile = toolPinFile == null || toolPinFile.isBlank()
                ? "ground-truth/tool-pins.tsv" : toolPinFile;
        pinCodeDigest = pinCodeDigest == null ? Boolean.FALSE : pinCodeDigest;
        enforce = enforce == null ? Boolean.TRUE : enforce;
        trustedPublishers = trustedPublishers == null ? List.of("local") : List.copyOf(trustedPublishers);
    }

    public static GroundTruthProperties defaults() {
        return new GroundTruthProperties(null, null, null, null, null, null, null, null);
    }
}
