package io.github.straightsang.agentsecurity.mcp.ensemble;

import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/*
 * 여러 탐지기의 판정을 코드가 결합해 최종 결정을 낸다. LLM은 한 표만 행사하고 결정은 하지 않는다.
 *
 * 1단계(싸고 빠름): 규칙, 어휘 탐지기
 *   - 규칙이 HIGH면 즉시 BLOCK (결정적 근거)
 *   - 둘 다 NONE이면 ALLOW (2단계 호출 없음)
 * 2단계(비싸고 느림): 외부 모델 탐지기. 1단계가 애매할 때만 호출한다.
 *
 * 결합(비대칭): 놓치는 비용이 더 크므로 의심 쪽에 기운다.
 *   - 규칙 HIGH, 또는 HIGH가 2표 이상  -> BLOCK
 *   - HIGH가 1표                       -> ESCALATE (의견 불일치 또는 단독 의심은 사람이 본다)
 *   - HIGH 없음, LOW가 2표 이상         -> ESCALATE
 *   - 그 밖                            -> ALLOW
 * 2단계 모델이 하나도 응답하지 못하면 투표 수가 줄 뿐이며, 1단계가 의심한 건 허용으로 바뀌지 않는다.
 */
@Service
public class EnsembleService {
    private final List<Detector> firstTier;
    private final List<Detector> secondTier;

    @Autowired
    public EnsembleService(EnsembleProperties properties) {
        this(List.of(new RuleDetector(), new LexicalInjectionDetector()),
                buildModelDetectors(properties));
    }

    public EnsembleService(List<Detector> firstTier, List<Detector> secondTier) {
        this.firstTier = List.copyOf(firstTier);
        this.secondTier = List.copyOf(secondTier);
    }

    private static List<Detector> buildModelDetectors(EnsembleProperties properties) {
        List<Detector> detectors = new ArrayList<>();
        for (int index = 0; index < properties.modelEndpoints().size(); index++) {
            detectors.add(new HttpModelDetector(
                    "model_" + (index + 1), properties.modelEndpoints().get(index), properties.timeout()));
        }
        return detectors;
    }

    public EnsembleVerdict assess(EvidencePacket packet) {
        List<DetectorResult> results = new ArrayList<>();
        for (Detector detector : firstTier) results.add(detector.assess(packet));

        for (DetectorResult result : results) {
            if (RuleDetector.ID.equals(result.detectorId()) && result.available()
                    && result.level() == DetectorLevel.HIGH) {
                return new EnsembleVerdict(EnsembleVerdict.Verdict.BLOCK, List.copyOf(results), false,
                        "결정적 규칙 위반: " + result.rationale());
            }
        }
        boolean allClear = results.stream()
                .allMatch(result -> !result.available() || result.level() == DetectorLevel.NONE);
        if (allClear) {
            return new EnsembleVerdict(EnsembleVerdict.Verdict.ALLOW, List.copyOf(results), false,
                    "1단계 탐지기 모두 이상 없음");
        }

        boolean usedSecondTier = !secondTier.isEmpty();
        for (Detector detector : secondTier) results.add(detector.assess(packet));

        long high = results.stream().filter(r -> r.available() && r.level() == DetectorLevel.HIGH).count();
        long low = results.stream().filter(r -> r.available() && r.level() == DetectorLevel.LOW).count();
        EnsembleVerdict.Verdict verdict;
        String rationale;
        if (high >= 2) {
            verdict = EnsembleVerdict.Verdict.BLOCK;
            rationale = "HIGH 판정이 " + high + "표입니다.";
        } else if (high == 1) {
            verdict = EnsembleVerdict.Verdict.ESCALATE;
            rationale = "HIGH 판정이 1표뿐이거나 탐지기 간 의견이 갈립니다. 사람 검토가 필요합니다.";
        } else if (low >= 2) {
            verdict = EnsembleVerdict.Verdict.ESCALATE;
            rationale = "LOW 판정이 " + low + "표입니다. 사람 검토가 필요합니다.";
        } else {
            verdict = EnsembleVerdict.Verdict.ALLOW;
            rationale = "단독 경고(LOW)만 있어 통과시키고 기록합니다.";
        }
        return new EnsembleVerdict(verdict, List.copyOf(results), usedSecondTier, rationale);
    }
}
