package io.github.straightsang.agentsecurity.mcp.ensemble;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/*
 * 도구 설명에서 프롬프트 인젝션과 유출 지시의 전형적인 표현을 찾는 가벼운 탐지기다.
 * 학습된 분류기(예: 파인튜닝한 GLiClass)를 대신하는 자리 표시자이자 1단계 필터이며, 모델이 아니다.
 * 보이지 않는 문자와 유니코드 변형으로 키워드를 숨기는 수법을 막기 위해 NFKC 정규화와 제로폭 문자 제거를 먼저 한다.
 * 점수는 일치한 패턴 가중치로 1 - Π(1 - w)를 계산한다. 0.7 이상이면 HIGH, 0.3 이상이면 LOW다.
 */
public class LexicalInjectionDetector implements Detector {
    public static final String ID = "lexical";
    private static final double HIGH_THRESHOLD = 0.7;
    private static final double LOW_THRESHOLD = 0.3;
    private static final Pattern INVISIBLE = Pattern.compile("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF]");

    private record Rule(String name, Pattern pattern, double weight) {
        static Rule of(String name, String regex, double weight) {
            return new Rule(name, Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE), weight);
        }
    }

    private static final List<Rule> RULES = List.of(
            Rule.of("이전 지시 무시", "ignore\\s+(all\\s+)?(the\\s+)?(previous|prior|above|earlier)\\s+(instructions|rules|messages)", 0.9),
            Rule.of("규칙 무시", "disregard\\s+.{0,30}(instructions|rules|polic)", 0.8),
            Rule.of("사용자에게 숨김", "do\\s+not\\s+(tell|inform|mention|reveal)\\b.{0,40}\\buser", 0.8),
            Rule.of("시스템 프롬프트 언급", "(system\\s+prompt|developer\\s+message|hidden\\s+instruction)", 0.4),
            Rule.of("가짜 시스템 태그", "(<\\s*important\\s*>|<\\s*system\\s*>|\\[\\s*system\\s*\\])", 0.6),
            Rule.of("외부 전송 지시", "(send|post|upload|exfiltrate|forward|leak)\\b.{0,60}(https?|ftp)://", 0.7),
            Rule.of("자격증명 파일 접근", "(read|cat|open|access|include)\\b.{0,40}(\\.ssh|id_rsa|\\.env\\b|/etc/passwd|credentials|private[_ ]key)", 0.8),
            Rule.of("인코딩 우회", "base64", 0.2),
            Rule.of("이전 지시 무시(한글)", "(이전|위의|앞선|기존)\\s*(지시|명령|규칙)(사항)?(을|를)?\\s*(모두\\s*)?무시", 0.9),
            Rule.of("사용자에게 숨김(한글)", "사용자(에게|한테)(는)?\\s*(말하지|알리지|보여주지)", 0.8),
            Rule.of("유출 지시(한글)", "(비밀번호|자격\\s*증명|개인키|토큰).{0,20}(전송|보내|유출|업로드)", 0.8));

    @Override
    public String id() {
        return ID;
    }

    @Override
    public DetectorResult assess(EvidencePacket packet) {
        List<String> matched = new ArrayList<>();
        double miss = 1.0;
        for (String raw : packet.untrustedText()) {
            String text = normalize(raw);
            if (!raw.equals(INVISIBLE.matcher(raw).replaceAll(""))) {
                matched.add("보이지 않는 제어 문자");
                miss *= 1.0 - 0.3;
            }
            for (Rule rule : RULES) {
                if (rule.pattern().matcher(text).find()) {
                    matched.add(rule.name());
                    miss *= 1.0 - rule.weight();
                }
            }
        }
        double score = Math.round((1.0 - miss) * 100.0) / 100.0;
        DetectorLevel level = score >= HIGH_THRESHOLD ? DetectorLevel.HIGH
                : score >= LOW_THRESHOLD ? DetectorLevel.LOW : DetectorLevel.NONE;
        String rationale = matched.isEmpty() ? "의심 표현 없음" : "일치: " + String.join(", ", matched);
        return DetectorResult.of(ID, level, score, rationale);
    }

    static String normalize(String text) {
        String stripped = INVISIBLE.matcher(text == null ? "" : text).replaceAll("");
        return Normalizer.normalize(stripped, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }
}
