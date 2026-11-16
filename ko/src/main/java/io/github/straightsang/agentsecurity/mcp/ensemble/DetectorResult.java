package io.github.straightsang.agentsecurity.mcp.ensemble;

/* available=false인 결과(모델 서버 장애 등)는 투표에서 제외한다. 허용으로 취급하지도 않는다. */
public record DetectorResult(
        String detectorId,
        DetectorLevel level,
        double score,
        String rationale,
        boolean available) {

    public static DetectorResult of(String id, DetectorLevel level, double score, String rationale) {
        return new DetectorResult(id, level, score, rationale, true);
    }

    public static DetectorResult unavailable(String id, String reason) {
        return new DetectorResult(id, DetectorLevel.NONE, 0.0, reason, false);
    }
}
