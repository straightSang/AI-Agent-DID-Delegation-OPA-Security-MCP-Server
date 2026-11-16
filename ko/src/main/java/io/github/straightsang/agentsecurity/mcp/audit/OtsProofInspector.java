package io.github.straightsang.agentsecurity.mcp.audit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

/*
 * .ots 파일의 구조와 대상 해시를 점검한다. 비트코인 확정 여부의 최종 검증은 공식 ots 클라이언트의 몫이다.
 * 여기서는 (1) 헤더가 올바른지, (2) 증명이 가리키는 해시가 우리 root 파일의 SHA-256과 같은지,
 * (3) 증명 안에 pending 또는 비트코인 attestation 태그가 있는지만 본다.
 */
public final class OtsProofInspector {
    private static final byte[] PENDING_TAG = {
            (byte) 0x83, (byte) 0xdf, (byte) 0xe3, 0x0d, 0x2e, (byte) 0xf9, 0x0c, (byte) 0x8e};
    private static final byte[] BITCOIN_TAG = {
            0x05, (byte) 0x88, (byte) 0x96, 0x0d, 0x73, (byte) 0xd7, 0x19, 0x01};

    public record Inspection(
            boolean headerValid,
            String targetDigestHex,
            boolean matchesRoot,
            boolean hasPendingAttestation,
            boolean hasBitcoinAttestation) {
    }

    private OtsProofInspector() {
    }

    public static Inspection inspect(Path otsFile, String merkleRoot) throws IOException {
        byte[] bytes = Files.readAllBytes(otsFile);
        int magicLength = OpenTimestampsAnchorService.HEADER_MAGIC.length;
        int digestStart = magicLength + 2;
        boolean headerValid = bytes.length > digestStart + 32
                && Arrays.equals(Arrays.copyOfRange(bytes, 0, magicLength),
                        OpenTimestampsAnchorService.HEADER_MAGIC)
                && bytes[magicLength] == OpenTimestampsAnchorService.MAJOR_VERSION
                && bytes[magicLength + 1] == OpenTimestampsAnchorService.OP_SHA256;
        if (!headerValid) return new Inspection(false, "", false, false, false);

        byte[] digest = Arrays.copyOfRange(bytes, digestStart, digestStart + 32);
        byte[] expected = sha256(merkleRoot.getBytes(StandardCharsets.UTF_8));
        byte[] body = Arrays.copyOfRange(bytes, digestStart + 32, bytes.length);
        return new Inspection(
                true, HexFormat.of().formatHex(digest), MessageDigest.isEqual(digest, expected),
                contains(body, PENDING_TAG), contains(body, BITCOIN_TAG));
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        for (int start = 0; start + needle.length <= haystack.length; start++) {
            boolean same = true;
            for (int offset = 0; offset < needle.length && same; offset++) {
                same = haystack[start + offset] == needle[offset];
            }
            if (same) return true;
        }
        return false;
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256을 사용할 수 없습니다.", exception);
        }
    }
}
