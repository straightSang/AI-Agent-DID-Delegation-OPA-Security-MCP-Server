package io.github.straightsang.agentsecurity.mcp.ensemble;

import java.util.List;

public record EnsembleVerdict(
        Verdict verdict,
        List<DetectorResult> results,
        boolean usedSecondTier,
        String rationale) {

    public enum Verdict {
        /** 문제 없음. */
        ALLOW,
        /** 사람이 확인해야 한다. 도구 등록은 격리하고, 요청은 통과시키되 원장에 남긴다. */
        ESCALATE,
        /** 차단한다. */
        BLOCK
    }
}
