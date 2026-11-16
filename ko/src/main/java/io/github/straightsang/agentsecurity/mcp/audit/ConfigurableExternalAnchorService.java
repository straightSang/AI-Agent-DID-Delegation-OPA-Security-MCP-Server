package io.github.straightsang.agentsecurity.mcp.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/* security.audit.anchor.type 설정에 따라 실제 앵커 구현을 고르는 하나뿐인 ExternalAnchorService 빈이다. */
@Service
public class ConfigurableExternalAnchorService implements ExternalAnchorService {
    private final ExternalAnchorService delegate;

    @Autowired
    public ConfigurableExternalAnchorService(AnchorProperties properties) {
        this.delegate = switch (properties.type()) {
            case "opentimestamps" -> new OpenTimestampsAnchorService(properties);
            case "disabled" -> new DisabledExternalAnchorService();
            default -> throw new IllegalStateException(
                    "지원하지 않는 앵커 종류입니다: " + properties.type());
        };
    }

    @Override
    public String anchor(String merkleRoot) {
        return delegate.anchor(merkleRoot);
    }
}
