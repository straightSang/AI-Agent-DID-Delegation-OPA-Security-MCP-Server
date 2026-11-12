package io.github.straightsang.agentsecurity.mcp.audit;

import org.springframework.stereotype.Service;

/* Returns the root without publishing it when no external anchor is configured locally. */
@Service
public class DisabledExternalAnchorService implements ExternalAnchorService {
    @Override
    public String anchor(String merkleRoot) {
        return "ANCHOR_DISABLED:" + merkleRoot;
    }
}
