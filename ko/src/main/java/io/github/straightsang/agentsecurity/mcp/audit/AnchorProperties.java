package io.github.straightsang.agentsecurity.mcp.audit;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/*
 * Merkle root를 어디에 고정할지 설정한다.
 * type: disabled(기본, 네트워크 게시 없음) 또는 opentimestamps
 * calendars: OpenTimestamps 캘린더 서버 URL 목록. 외부로 나가는 것은 root의 SHA-256 해시뿐이다.
 * directory: 캘린더가 돌려준 .ots 증명 파일과 root 파일을 저장할 폴더
 */
@ConfigurationProperties(prefix = "security.audit.anchor")
public record AnchorProperties(String type, List<String> calendars, String directory) {
    public AnchorProperties {
        type = type == null || type.isBlank() ? "disabled" : type.trim().toLowerCase();
        calendars = calendars == null || calendars.isEmpty()
                ? List.of("https://alice.btc.calendar.opentimestamps.org",
                        "https://bob.btc.calendar.opentimestamps.org")
                : List.copyOf(calendars);
        directory = directory == null || directory.isBlank() ? "audit-anchors/ots" : directory;
    }
}
