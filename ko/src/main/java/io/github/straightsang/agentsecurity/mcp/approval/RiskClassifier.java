package io.github.straightsang.agentsecurity.mcp.approval;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

/*
 * 요청의 action, resource, arguments를 보고 사용자 승인이 필요한 위험인지 분류한다.
 *
 * 검사 전에 문자열을 정규화한다: 유니코드 NFKC, 소문자, 보이지 않는 문자 제거, 퍼센트 인코딩 두 번 해제, 역슬래시를 슬래시로.
 * 인코딩이나 전각 문자로 키워드를 숨기는 우회를 줄이기 위해서다.
 *
 * CRITICAL/DENY : 비밀정보, 자격증명 파일, 경로 탈출(../, 절대 경로, null 바이트, file://)
 * HIGH/승인 필요 : 개인정보, 외부 전송, 삭제/실행 같은 되돌리기 어려운 행동
 * MEDIUM/기록    : 쓰기, 수정
 * LOW/허용       : 그 밖의 읽기 전용 요청
 */
@Service
public class RiskClassifier {
    private static final Pattern INVISIBLE = Pattern.compile("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF]");
    private static final Pattern DRIVE_LETTER = Pattern.compile("(^|[\\s\"'=:,\\[{(])[a-z]:/");
    private static final Pattern ABSOLUTE_PATH = Pattern.compile("(^|[\\s\"'=,\\[{(])/[a-z0-9._-]");
    private static final Set<String> HIGH_WORDS = Set.of(
            "post", "put", "upload", "webhook", "curl", "wget", "exec", "execute", "shell", "bash",
            "delete", "remove", "drop", "truncate", "send", "export", "email", "phone", "external", "personal");

    public RiskAssessment assess(
            String action,
            String resource,
            Map<String, Object> arguments,
            String target) {
        String combined = normalize(action + " " + resource + " " + arguments + " " + target);
        List<String> risks = new ArrayList<>();

        if (containsAny(combined, "secret", "private_key", "private key", "privatekey", "credential",
                "password", "api_key", "apikey", "access_token", "비밀번호", "비밀키", "개인키", "자격증명")) {
            risks.add("비밀정보 또는 자격증명에 접근할 가능성이 있습니다.");
            return deny(action, target, risks);
        }
        if (containsAny(combined, ".env", "id_rsa", "id_ed25519", ".ssh/", "/etc/passwd", "/etc/shadow",
                ".pem", ".pkcs8", ".aws/", "kubeconfig", ".kube/")) {
            risks.add("자격증명 또는 시스템 설정 파일에 접근할 가능성이 있습니다.");
            return deny(action, target, risks);
        }
        if (combined.contains("../") || combined.contains("file://") || combined.contains("[nul]")
                || DRIVE_LETTER.matcher(combined).find() || ABSOLUTE_PATH.matcher(combined).find()) {
            risks.add("허용된 폴더 밖의 경로에 접근하려는 시도로 보입니다(경로 탈출).");
            return deny(action, target, risks);
        }

        Set<String> words = new HashSet<>(Arrays.asList(combined.split("[^\\p{L}\\p{N}]+")));
        boolean highWord = words.stream().anyMatch(HIGH_WORDS::contains);
        if (highWord || containsAny(combined, "personal", "email", "phone", "external", "send", "export",
                "http://", "https://", "개인정보", "주민등록", "전화번호", "이메일", "외부", "전송", "내보내")) {
            risks.add("개인정보 또는 내부 데이터가 외부로 전달되거나, 되돌리기 어려운 변경이 일어날 수 있습니다.");
            risks.add("전달 후에는 데이터를 회수하기 어려울 수 있습니다.");
            return new RiskAssessment(
                    RiskLevel.HIGH, DecisionType.REQUIRE_APPROVAL,
                    action + " 실행", target, List.copyOf(risks));
        }

        if (containsAny(combined, "write", "update", "modify", "create", "append", "rename")) {
            risks.add("파일 또는 시스템 상태가 변경됩니다.");
            return new RiskAssessment(
                    RiskLevel.MEDIUM, DecisionType.ALLOW_LOG,
                    action + " 실행", target, List.copyOf(risks));
        }

        return new RiskAssessment(
                RiskLevel.LOW, DecisionType.ALLOW,
                action + " 실행", target, List.of("읽기 전용 또는 낮은 위험의 요청입니다."));
    }

    private RiskAssessment deny(String action, String target, List<String> risks) {
        return new RiskAssessment(
                RiskLevel.CRITICAL, DecisionType.DENY, action + " 실행", target, List.copyOf(risks));
    }

    static String normalize(String value) {
        String text = Normalizer.normalize(value == null ? "" : value, Normalizer.Form.NFKC);
        for (int round = 0; round < 2; round++) text = percentDecode(INVISIBLE.matcher(text).replaceAll(""));
        return INVISIBLE.matcher(text).replaceAll("").replace("\u0000", "[nul]")
                .toLowerCase(Locale.ROOT).replace('\\', '/');
    }

    private static String percentDecode(String text) {
        if (!text.contains("%")) return text;
        try {
            return URLDecoder.decode(text.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException exception) {
            return text;
        }
    }

    private boolean containsAny(String value, String... candidates) {
        for (String candidate : candidates) {
            if (value.contains(candidate)) return true;
        }
        return false;
    }
}
