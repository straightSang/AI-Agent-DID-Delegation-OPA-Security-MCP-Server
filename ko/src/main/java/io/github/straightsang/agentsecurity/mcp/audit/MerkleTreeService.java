package io.github.straightsang.agentsecurity.mcp.audit;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.springframework.stereotype.Service;

/*
 * 여러 감사 이벤트 해시를 하나의 Merkle root로 요약한다.
 *
 * calculateRoot/root: 기존 AuditLedgerService와의 호환을 위한 방식이다. 홀수 노드를 복제하므로
 *                     서로 다른 이벤트 목록이 같은 root를 만들 수 있어 새 코드에는 쓰지 않는다.
 * rfc6962Root 등:     RFC 6962/9162 방식이다. 리프(0x00)와 내부 노드(0x01)를 도메인 분리하고
 *                     홀수 노드를 복제하지 않으며, 포함 증명(inclusion proof)을 만들고 검증한다.
 */
@Service
public class MerkleTreeService {
    private static final byte LEAF_PREFIX = 0x00;
    private static final byte NODE_PREFIX = 0x01;

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

    /* RFC 6962 방식의 Merkle root를 계산한다. */
    public String rfc6962Root(List<String> eventHashes) {
        List<byte[]> leaves = parseLeaves(eventHashes);
        return HexFormat.of().formatHex(subtreeHash(leaves, 0, leaves.size()));
    }

    /* index번째 이벤트가 root에 포함됨을 보이는 형제 해시 목록(audit path)을 만든다. */
    public List<String> auditPath(List<String> eventHashes, int index) {
        List<byte[]> leaves = parseLeaves(eventHashes);
        if (index < 0 || index >= leaves.size()) {
            throw new IllegalArgumentException("이벤트 위치가 범위를 벗어났습니다.");
        }
        List<byte[]> path = new ArrayList<>();
        collectPath(leaves, index, 0, leaves.size(), path);
        return path.stream().map(value -> HexFormat.of().formatHex(value)).toList();
    }

    /* 이벤트 해시와 audit path로 root를 다시 계산해 기대한 root와 같은지 확인한다. */
    public boolean verifyInclusion(
            String leafEventHash, long leafIndex, long treeSize,
            List<String> path, String expectedRoot) {
        try {
            if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) return false;
            long fn = leafIndex;
            long sn = treeSize - 1;
            byte[] result = leafHash(HexFormat.of().parseHex(leafEventHash));
            for (String encoded : path) {
                byte[] sibling = HexFormat.of().parseHex(encoded);
                if (sn == 0) return false;
                if ((fn & 1) == 1 || fn == sn) {
                    result = nodeHash(sibling, result);
                    if ((fn & 1) == 0) {
                        while ((fn & 1) == 0 && fn != 0) {
                            fn >>= 1;
                            sn >>= 1;
                        }
                    }
                } else {
                    result = nodeHash(result, sibling);
                }
                fn >>= 1;
                sn >>= 1;
            }
            return sn == 0 && MessageDigest.isEqual(result, HexFormat.of().parseHex(expectedRoot));
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private List<byte[]> parseLeaves(List<String> eventHashes) {
        if (eventHashes == null || eventHashes.isEmpty()) {
            throw new IllegalArgumentException("Merkle root를 만들 이벤트가 없습니다.");
        }
        return eventHashes.stream().map(value -> HexFormat.of().parseHex(value)).toList();
    }

    private byte[] subtreeHash(List<byte[]> leaves, int from, int to) {
        int size = to - from;
        if (size == 1) return leafHash(leaves.get(from));
        int split = largestPowerOfTwoBelow(size);
        return nodeHash(subtreeHash(leaves, from, from + split), subtreeHash(leaves, from + split, to));
    }

    private void collectPath(List<byte[]> leaves, int index, int from, int to, List<byte[]> path) {
        int size = to - from;
        if (size == 1) return;
        int split = largestPowerOfTwoBelow(size);
        if (index < from + split) {
            collectPath(leaves, index, from, from + split, path);
            path.add(subtreeHash(leaves, from + split, to));
        } else {
            collectPath(leaves, index, from + split, to, path);
            path.add(subtreeHash(leaves, from, from + split));
        }
    }

    private int largestPowerOfTwoBelow(int size) {
        int power = 1;
        while ((power << 1) < size) power <<= 1;
        return power;
    }

    private byte[] leafHash(byte[] value) {
        byte[] input = new byte[value.length + 1];
        input[0] = LEAF_PREFIX;
        System.arraycopy(value, 0, input, 1, value.length);
        return sha256(input);
    }

    private byte[] nodeHash(byte[] left, byte[] right) {
        byte[] input = new byte[left.length + right.length + 1];
        input[0] = NODE_PREFIX;
        System.arraycopy(left, 0, input, 1, left.length);
        System.arraycopy(right, 0, input, 1 + left.length, right.length);
        return sha256(input);
    }

    private byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Merkle hash 계산에 실패했습니다.", exception);
        }
    }
}
