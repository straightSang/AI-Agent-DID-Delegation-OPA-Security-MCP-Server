package io.github.straightsang.agentsecurity.mcp.ensemble;

import java.util.ArrayList;
import java.util.List;

/*
 * 결정적 규칙 탐지기다. 같은 입력은 항상 같은 결과를 내고, 앙상블에서 유일하게 단독으로 BLOCK을 만들 수 있다.
 * 사용하는 사실(fact):
 *   highFindings, mediumFindings: 권한 그래프 이상 징후 개수
 *   descriptionChanged, codeChanged: 도구 설명/코드 해시가 고정값과 달라졌는지
 *   publisherTrusted=false: 게시자가 신뢰 목록에 없는지
 */
public class RuleDetector implements Detector {
    public static final String ID = "rules";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public DetectorResult assess(EvidencePacket packet) {
        List<String> high = new ArrayList<>();
        if (packet.count("highFindings") > 0) {
            high.add("그래프 규칙 위반 " + packet.count("highFindings") + "건(" + packet.facts().getOrDefault("findingTypes", "") + ")");
        }
        if (packet.flag("descriptionChanged")) high.add("도구 설명이 고정된 값과 다릅니다(rug pull 의심)");
        if (packet.flag("codeChanged")) high.add("도구 코드 해시가 고정된 값과 다릅니다");
        if ("false".equals(packet.facts().get("publisherTrusted"))) high.add("신뢰 목록에 없는 게시자입니다");
        if (!high.isEmpty()) {
            return DetectorResult.of(ID, DetectorLevel.HIGH, 1.0, String.join("; ", high));
        }
        if (packet.count("mediumFindings") > 0) {
            return DetectorResult.of(ID, DetectorLevel.LOW, 0.4,
                    "주의 수준 이상 징후 " + packet.count("mediumFindings") + "건");
        }
        return DetectorResult.of(ID, DetectorLevel.NONE, 0.0, "규칙 위반 없음");
    }
}
