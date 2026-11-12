package io.github.straightsang.agentsecurity.mcp.audit;

import org.springframework.stereotype.Service;

/* 외부 앵커가 설정되지 않은 로컬 환경에서는 root만 반환하고 네트워크 게시를 하지 않는다. */
@Service
public class DisabledExternalAnchorService implements ExternalAnchorService {
    @Override
    public String anchor(String merkleRoot) {
        return "ANCHOR_DISABLED:" + merkleRoot;
    }
}
