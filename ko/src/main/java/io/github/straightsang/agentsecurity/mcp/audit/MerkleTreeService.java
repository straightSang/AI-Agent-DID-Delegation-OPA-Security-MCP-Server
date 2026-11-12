package io.github.straightsang.agentsecurity.mcp.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.springframework.stereotype.Service;

/* 여러 감사 이벤트 해시를 하나의 Merkle root로 요약한다. */
@Service
public class MerkleTreeService {
    /* 기존 AuditLedgerService와의 호환을 위한 이름이다. */
    public String root(List<String> eventHashes) {
        return calculateRoot(eventHashes);
    }

    public String calculateRoot(List<String> eventHashes) {
        if (eventHashes == null || eventHashes.isEmpty()) {
            throw new IllegalArgumentException("Merkle root를 만들 이벤트가 없습니다.");
        }
        List<byte[]> level = eventHashes.stream()
                .map(value -> HexFormat.of().parseHex(value))
                .toList();
        while (level.size() > 1) {
            List<byte[]> next = new ArrayList<>();
            for (int index = 0; index < level.size(); index += 2) {
                byte[] left = level.get(index);
                byte[] right = index + 1 < level.size() ? level.get(index + 1) : left;
                byte[] combined = new byte[left.length + right.length];
                System.arraycopy(left, 0, combined, 0, left.length);
                System.arraycopy(right, 0, combined, left.length, right.length);
                next.add(sha256(combined));
            }
            level = next;
        }
        return HexFormat.of().formatHex(level.getFirst());
    }

    private byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Merkle hash 계산에 실패했습니다.", exception);
        }
    }
}
