package io.github.straightsang.agentsecurity.mcp.ensemble;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * 외부 판정 모델(LLM, 분류기 서버)을 HTTP로 호출하는 어댑터다. 모델 자체는 포함하지 않는다.
 *
 * 요청: POST {endpoint}, JSON {"kind","subjectId","facts":{...},"snippets":[...]}
 * 응답: JSON {"level":"NONE|LOW|HIGH","score":0.0~1.0,"rationale":"..."}
 *
 * 안전 장치
 *  - 응답에서 level과 score만 엄격한 정규식으로 꺼낸다. 그 밖의 텍스트는 버린다(모델 출력이 인젝션에 오염돼도 영향이 없다).
 *  - 형식이 틀리거나 서버가 응답하지 않으면 "투표 불가"로 처리한다. 허용으로 보지 않는다.
 *  - 이 어댑터가 보내는 snippets는 외부에서 온 신뢰할 수 없는 텍스트다. 모델 서버 쪽에서 지시문이 아니라 분석 대상 데이터로만
 *    다루도록 프롬프트를 격리하고, 판정 모델에는 어떤 도구 권한도 주지 않아야 한다.
 */
public class HttpModelDetector implements Detector {
    private static final Pattern LEVEL = Pattern.compile("\"level\"\\s*:\\s*\"(NONE|LOW|HIGH)\"");
    private static final Pattern SCORE = Pattern.compile("\"score\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)");

    private final String id;
    private final URI endpoint;
    private final Duration timeout;
    private final HttpClient httpClient;

    public HttpModelDetector(String id, String endpoint, Duration timeout) {
        this(id, endpoint, timeout, HttpClient.newBuilder().connectTimeout(timeout).build());
    }

    HttpModelDetector(String id, String endpoint, Duration timeout, HttpClient httpClient) {
        this.id = id;
        this.endpoint = URI.create(endpoint);
        this.timeout = timeout;
        this.httpClient = httpClient;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public DetectorResult assess(EvidencePacket packet) {
        try {
            HttpRequest request = HttpRequest.newBuilder(endpoint)
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(toJson(packet), StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return DetectorResult.unavailable(id, "HTTP " + response.statusCode());
            }
            Matcher level = LEVEL.matcher(response.body());
            if (!level.find()) return DetectorResult.unavailable(id, "응답 형식 오류");
            double score = 0.0;
            Matcher scoreMatcher = SCORE.matcher(response.body());
            if (scoreMatcher.find()) score = Math.max(0.0, Math.min(1.0, Double.parseDouble(scoreMatcher.group(1))));
            return DetectorResult.of(id, DetectorLevel.valueOf(level.group(1)), score, "외부 모델 판정");
        } catch (IOException | RuntimeException exception) {
            return DetectorResult.unavailable(id, exception.getClass().getSimpleName());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return DetectorResult.unavailable(id, "interrupted");
        }
    }

    static String toJson(EvidencePacket packet) {
        StringBuilder json = new StringBuilder("{");
        json.append("\"kind\":").append(quote(packet.kind()));
        json.append(",\"subjectId\":").append(quote(packet.subjectId()));
        json.append(",\"facts\":{");
        boolean first = true;
        for (Map.Entry<String, String> entry : new TreeMap<>(packet.facts()).entrySet()) {
            if (!first) json.append(',');
            json.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));
            first = false;
        }
        json.append("},\"snippets\":[");
        for (int index = 0; index < packet.untrustedText().size(); index++) {
            if (index > 0) json.append(',');
            json.append(quote(packet.untrustedText().get(index)));
        }
        return json.append("]}").toString();
    }

    static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : (value == null ? "" : value).toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.append('"').toString();
    }
}
