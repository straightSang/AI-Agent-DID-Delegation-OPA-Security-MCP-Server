package io.github.straightsang.agentsecurity.mcp.groundtruth;

import io.github.straightsang.agentsecurity.mcp.approval.DecisionType;
import io.github.straightsang.agentsecurity.mcp.approval.RiskAssessment;
import io.github.straightsang.agentsecurity.mcp.approval.RiskLevel;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import io.github.straightsang.agentsecurity.mcp.ensemble.EnsembleService;
import io.github.straightsang.agentsecurity.mcp.ensemble.EnsembleVerdict;
import io.github.straightsang.agentsecurity.mcp.ensemble.EvidencePacket;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/*
 * 요청 한 건에 Ground Truth를 적용하는 검문소다. SecurityGateway에서 위임 검증 직후에 호출한다.
 *
 *  1. 도구 계보 확인: 격리됐거나 등록되지 않은 도구는 바로 거부한다.
 *  2. 그래프 갱신: 검증을 통과한 위임 체인을 그래프(원장)에 반영한다.
 *  3. 증거 추출: 코드가 그래프에서 이상 징후를 뽑고, 요청 인자의 문자열을 신뢰하지 않는 텍스트로 모은다.
 *  4. 앙상블 판정: BLOCK이면 거부(enforce=true일 때), ESCALATE면 사람 승인을 요구하도록 위험도를 올린다.
 */
@Component
public class GroundTruthGuard {
    public record Outcome(EnsembleVerdict verdict, List<PermissionGraph.Finding> findings, String note) {
        public boolean escalate() {
            return verdict.verdict() == EnsembleVerdict.Verdict.ESCALATE;
        }
    }

    private final ToolProvenanceService toolProvenance;
    private final PermissionGraphService graphService;
    private final EnsembleService ensembleService;
    private final GroundTruthProperties properties;

    public GroundTruthGuard(
            ToolProvenanceService toolProvenance,
            PermissionGraphService graphService,
            EnsembleService ensembleService,
            GroundTruthProperties properties) {
        this.toolProvenance = toolProvenance;
        this.graphService = graphService;
        this.ensembleService = ensembleService;
        this.properties = properties;
    }

    public Outcome inspect(
            String requestId, String toolName, List<DelegationToken> verifiedChain,
            Map<String, Object> arguments, String resource) {
        if (!toolProvenance.isUsable(toolName)) {
            ToolProvenanceService.ToolState state = toolProvenance.state(toolName);
            throw new AccessDeniedException(state == null
                    ? "등록되지 않은 도구입니다: " + toolName
                    : "격리된 도구입니다: " + toolName + " (" + state.reason() + ")");
        }
        graphService.ingestChain(verifiedChain, requestId);
        List<PermissionGraph.Finding> findings = graphService.findingsForChain(verifiedChain, Instant.now());
        EvidencePacket packet = buildPacket(requestId, toolName, findings, arguments, resource);
        EnsembleVerdict verdict = ensembleService.assess(packet);
        String note = "gt:" + verdict.verdict() + (findings.isEmpty() ? "" : " findings=" + summarize(findings));
        if (verdict.verdict() == EnsembleVerdict.Verdict.BLOCK && properties.enforce()) {
            throw new AccessDeniedException("Ground Truth 검사에서 차단되었습니다: " + verdict.rationale());
        }
        return new Outcome(verdict, List.copyOf(findings), note);
    }

    /* 앙상블이 사람 검토를 요구하면 위험도를 HIGH/승인 필요로 올린다. 이미 DENY인 요청은 그대로 둔다. */
    public RiskAssessment applyEscalation(RiskAssessment assessment, Outcome outcome) {
        if (!outcome.escalate() || assessment.decision() == DecisionType.DENY
                || assessment.decision() == DecisionType.REQUIRE_APPROVAL) {
            return assessment;
        }
        List<String> risks = new ArrayList<>(assessment.risks());
        risks.add("Ground Truth 검사에서 사람 검토가 필요하다고 판정했습니다: " + outcome.verdict().rationale());
        return new RiskAssessment(RiskLevel.HIGH, DecisionType.REQUIRE_APPROVAL,
                assessment.executionSummary(), assessment.target(), List.copyOf(risks));
    }

    private EvidencePacket buildPacket(
            String requestId, String toolName, List<PermissionGraph.Finding> findings,
            Map<String, Object> arguments, String resource) {
        long high = findings.stream().filter(f -> f.severity() == PermissionGraph.Severity.HIGH).count();
        long medium = findings.stream().filter(f -> f.severity() == PermissionGraph.Severity.MEDIUM).count();
        Set<String> types = new LinkedHashSet<>();
        findings.forEach(f -> types.add(f.type()));
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("highFindings", Long.toString(high));
        facts.put("mediumFindings", Long.toString(medium));
        facts.put("findingTypes", String.join(",", types));
        facts.put("tool", toolName);
        List<String> text = new ArrayList<>();
        if (resource != null) text.add(resource);
        collectStrings(arguments, text);
        return new EvidencePacket("request", requestId, facts, text);
    }

    @SuppressWarnings("unchecked")
    private void collectStrings(Object value, List<String> out) {
        if (value instanceof String text) out.add(text);
        else if (value instanceof Map<?, ?> map) map.values().forEach(item -> collectStrings(item, out));
        else if (value instanceof Iterable<?> items) items.forEach(item -> collectStrings(item, out));
    }

    private String summarize(List<PermissionGraph.Finding> findings) {
        return String.join(",", findings.stream().map(f -> f.type() + "(" + f.severity() + ")").distinct().toList());
    }
}
