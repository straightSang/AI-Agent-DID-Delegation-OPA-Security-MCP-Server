package io.github.straightsang.agentsecurity.mcp.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class MerkleTreeServiceTest {
    private final MerkleTreeService merkle = new MerkleTreeService();

    private List<String> leaves(int count) throws Exception {
        List<String> result = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            result.add(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(("event-" + index).getBytes(StandardCharsets.UTF_8))));
        }
        return result;
    }

    @Test
    void singleLeafRootIsDomainSeparatedLeafHash() throws Exception {
        List<String> one = leaves(1);
        byte[] input = new byte[33];
        System.arraycopy(HexFormat.of().parseHex(one.getFirst()), 0, input, 1, 32);
        String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        assertThat(merkle.rfc6962Root(one)).isEqualTo(expected);
    }

    @Test
    void everyLeafHasVerifiableInclusionProofForEveryTreeSize() throws Exception {
        for (int size = 1; size <= 17; size++) {
            List<String> all = leaves(size);
            String root = merkle.rfc6962Root(all);
            for (int index = 0; index < size; index++) {
                List<String> path = merkle.auditPath(all, index);
                assertThat(merkle.verifyInclusion(all.get(index), index, size, path, root)).isTrue();
            }
        }
    }

    @Test
    void rejectsWrongLeafWrongIndexWrongSizeAndTamperedPath() throws Exception {
        List<String> all = leaves(7);
        String root = merkle.rfc6962Root(all);
        List<String> path = merkle.auditPath(all, 3);
        assertThat(merkle.verifyInclusion(all.get(4), 3, 7, path, root)).isFalse();
        assertThat(merkle.verifyInclusion(all.get(3), 2, 7, path, root)).isFalse();
        // 경로 길이가 맞지 않는 treeSize는 거부한다. (경로 길이가 같은 크기 차이는 증명만으로 구분되지 않고, 체크포인트 서명이 treeSize를 고정한다.)
        assertThat(merkle.verifyInclusion(all.get(3), 3, 16, path, root)).isFalse();
        List<String> tampered = new ArrayList<>(path);
        tampered.set(0, "f".repeat(64));
        assertThat(merkle.verifyInclusion(all.get(3), 3, 7, tampered, root)).isFalse();
        assertThat(merkle.verifyInclusion(all.get(3), 3, 7, path, "0".repeat(64))).isFalse();
    }

    @Test
    void differentEventListsDoNotShareRootEvenWhenLastLeafRepeats() throws Exception {
        List<String> three = leaves(3);
        List<String> four = new ArrayList<>(three);
        four.add(three.get(2));
        assertThat(merkle.rfc6962Root(three)).isNotEqualTo(merkle.rfc6962Root(four));
        // 기존 방식은 홀수 노드를 복제하므로 이 두 목록이 같은 root를 만든다. 새 방식과의 차이를 확인한다.
        assertThat(merkle.calculateRoot(three)).isEqualTo(merkle.calculateRoot(four));
    }
}
