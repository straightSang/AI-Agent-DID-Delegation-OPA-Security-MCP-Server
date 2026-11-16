package io.github.straightsang.agentsecurity.mcp.audit;

import java.util.List;

/* 해시 체인, 체크포인트 서명, 꼬리 절단, 재작성, 외부 앵커 상태를 한 번에 보여주는 검증 결과다. */
public record LedgerVerificationReport(
        boolean ok,
        boolean chainValid,
        int checkpointsChecked,
        List<String> failures,
        List<String> warnings) {
}
