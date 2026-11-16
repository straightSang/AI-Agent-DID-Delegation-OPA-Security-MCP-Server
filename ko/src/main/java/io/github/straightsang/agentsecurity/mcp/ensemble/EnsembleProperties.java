package io.github.straightsang.agentsecurity.mcp.ensemble;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/*
 * 2단계 판정 모델 서버 주소. 비어 있으면 규칙과 어휘 탐지기만 쓰고, 애매한 건 사람 검토로 넘긴다.
 * 서로 다른 계열의 모델을 섞을수록 오류가 덜 겹쳐 앙상블 효과가 커진다.
 */
@ConfigurationProperties(prefix = "security.ground-truth.ensemble")
public record EnsembleProperties(List<String> modelEndpoints, Duration timeout) {
    public EnsembleProperties {
        modelEndpoints = modelEndpoints == null ? List.of()
                : modelEndpoints.stream().filter(value -> value != null && !value.isBlank()).toList();
        timeout = timeout == null ? Duration.ofSeconds(8) : timeout;
    }

    public static EnsembleProperties defaults() {
        return new EnsembleProperties(null, null);
    }
}
