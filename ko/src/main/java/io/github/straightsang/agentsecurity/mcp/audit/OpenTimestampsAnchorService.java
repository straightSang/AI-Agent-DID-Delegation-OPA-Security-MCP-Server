package io.github.straightsang.agentsecurity.mcp.audit;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/*
 * Merkle root를 OpenTimestamps 캘린더 서버에 제출하고, 공식 ots 클라이언트가 읽을 수 있는 .ots 증명을 저장한다.
 *
 * 동작
 *  1. root(16진수 문자열)를 담은 "<root>.root" 파일을 만든다. 이 파일의 SHA-256이 타임스탬프 대상이다.
 *  2. 각 캘린더에 해시 32바이트를 POST한다. 캘린더는 "곧 비트코인에 포함될 것"이라는 pending 증명을 돌려준다.
 *  3. 응답 앞에 .ots 헤더(매직, 버전, SHA-256 연산, 해시)를 붙여 "<root>.<캘린더>.ots"로 저장한다.
 *
 * 한계
 *  - 저장되는 증명은 pending 상태다. 비트코인 블록 확정까지 수 시간이 걸린다.
 *    확정 증명은 공식 클라이언트로 받아 검증한다: ots upgrade <파일>.ots, ots verify <파일>.ots
 *  - OpenTimestamps는 "그 시점 이전에 존재했다"만 증명한다. 누가 썼는지는 증명하지 않는다.
 *  - 이 클래스는 비트코인 증명을 직접 검증하지 않는다. OtsProofInspector는 구조와 대상 해시만 점검한다.
 */
public class OpenTimestampsAnchorService implements ExternalAnchorService {
    static final byte[] HEADER_MAGIC = {
            0x00, 'O', 'p', 'e', 'n', 'T', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p', 's', 0x00,
            0x00, 'P', 'r', 'o', 'o', 'f', 0x00,
            (byte) 0xbf, (byte) 0x89, (byte) 0xe2, (byte) 0xe8, (byte) 0x84, (byte) 0xe8,
            (byte) 0x92, (byte) 0x94};
    static final byte MAJOR_VERSION = 0x01;
    static final byte OP_SHA256 = 0x08;

    private final List<String> calendars;
    private final Path directory;
    private final HttpClient httpClient;

    public OpenTimestampsAnchorService(AnchorProperties properties) {
        this(properties.calendars(), Path.of(properties.directory()),
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build());
    }

    OpenTimestampsAnchorService(List<String> calendars, Path directory, HttpClient httpClient) {
        this.calendars = List.copyOf(calendars);
        this.directory = directory.toAbsolutePath().normalize();
        this.httpClient = httpClient;
    }

    @Override
    public String anchor(String merkleRoot) {
        if (merkleRoot == null || !merkleRoot.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Merkle root 형식이 올바르지 않습니다.");
        }
        byte[] rootFileBytes = merkleRoot.getBytes(StandardCharsets.UTF_8);
        byte[] digest = sha256(rootFileBytes);
        List<String> saved = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        try {
            Files.createDirectories(directory);
            Path rootFile = directory.resolve(merkleRoot + ".root");
            if (!Files.exists(rootFile)) Files.write(rootFile, rootFileBytes, StandardOpenOption.CREATE_NEW);
        } catch (IOException exception) {
            return "OTS_FAILED:" + merkleRoot + ":저장 폴더를 만들 수 없습니다";
        }

        for (String calendar : calendars) {
            try {
                byte[] timestamp = submit(calendar, digest);
                if (timestamp.length == 0) throw new IOException("빈 응답");
                String fileName = merkleRoot + "." + hostLabel(calendar) + ".ots";
                Files.write(directory.resolve(fileName), buildProof(digest, timestamp),
                        StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                saved.add(fileName);
            } catch (IOException | RuntimeException exception) {
                failed.add(hostLabel(calendar) + "=" + exception.getClass().getSimpleName());
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                failed.add(hostLabel(calendar) + "=interrupted");
            }
        }
        if (saved.isEmpty()) return "OTS_FAILED:" + merkleRoot + ":" + String.join(",", failed);
        return "OTS_PENDING:" + merkleRoot + ":" + String.join(",", saved);
    }

    /* .ots 파일 = 매직 + 버전 + SHA-256 연산 + 해시 32바이트 + 캘린더가 돌려준 타임스탬프 */
    static byte[] buildProof(byte[] digest, byte[] timestamp) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(HEADER_MAGIC);
        output.write(MAJOR_VERSION);
        output.write(OP_SHA256);
        output.writeBytes(digest);
        output.writeBytes(timestamp);
        return output.toByteArray();
    }

    private byte[] submit(String calendar, byte[] digest) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(stripSlash(calendar) + "/digest"))
                .timeout(Duration.ofSeconds(10))
                .header("Accept", "application/vnd.opentimestamps.v1")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("User-Agent", "agent-security-mcp-anchor")
                .POST(HttpRequest.BodyPublishers.ofByteArray(digest))
                .build();
        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) throw new IOException("HTTP " + response.statusCode());
        return response.body();
    }

    private String stripSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private String hostLabel(String calendar) {
        String host = URI.create(calendar).getHost();
        int port = URI.create(calendar).getPort();
        String label = (host == null ? "calendar" : host) + (port > 0 ? "-" + port : "");
        return label.replaceAll("[^A-Za-z0-9.-]", "_");
    }

    private byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256을 사용할 수 없습니다.", exception);
        }
    }
}
