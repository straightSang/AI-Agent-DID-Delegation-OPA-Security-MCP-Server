package io.github.straightsang.agentsecurity.mcp.ensemble;

import java.util.List;
import java.util.Map;

/*
 * 탐지기에 넘기는 증거 묶음이다.
 * facts: 코드가 Ground Truth에서 뽑은 구조화된 사실(신뢰할 수 있음)
 * untrustedText: 도구 설명처럼 외부에서 온 텍스트(신뢰할 수 없음, 길이를 제한해 전달)
 */
public record EvidencePacket(
        String kind,
        String subjectId,
        Map<String, String> facts,
        List<String> untrustedText) {
    public static final int MAX_TEXT_LENGTH = 2000;

    public EvidencePacket {
        facts = facts == null ? Map.of() : Map.copyOf(facts);
        untrustedText = untrustedText == null ? List.of() : untrustedText.stream()
                .map(text -> text == null ? "" : text)
                .map(text -> text.length() > MAX_TEXT_LENGTH ? text.substring(0, MAX_TEXT_LENGTH) : text)
                .toList();
    }

    public boolean flag(String key) {
        return "true".equals(facts.get(key));
    }

    public int count(String key) {
        try {
            return Integer.parseInt(facts.getOrDefault(key, "0"));
        } catch (NumberFormatException exception) {
            return 0;
        }
    }
}
