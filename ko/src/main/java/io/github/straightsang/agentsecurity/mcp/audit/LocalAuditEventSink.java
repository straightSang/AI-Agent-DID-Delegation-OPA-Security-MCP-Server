package io.github.straightsang.agentsecurity.mcp.audit;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!aws")
public class LocalAuditEventSink implements AuditEventSink {
    @Override public void store(AuditLedgerEntry entry) {
        // 로컬에서는 AuditLedgerService 메모리 체인과 파일 체크포인트만 사용한다.
    }
}
