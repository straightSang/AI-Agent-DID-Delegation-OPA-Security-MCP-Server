package io.github.straightsang.agentsecurity.mcp.groundtruth;

import io.github.straightsang.agentsecurity.mcp.approval.ApprovalService;
import io.github.straightsang.agentsecurity.mcp.approval.ApprovalToken;
import io.github.straightsang.agentsecurity.mcp.audit.SignedAuditLedger;
import io.github.straightsang.agentsecurity.mcp.ensemble.EnsembleService;
import io.github.straightsang.agentsecurity.mcp.ensemble.EnsembleVerdict;
import io.github.straightsang.agentsecurity.mcp.ensemble.EvidencePacket;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/*
 * 도구의 계보(provenance)를 관리한다. 공급망 공격 중 "도구 설명이 승인 뒤에 바뀌는" rug pull을 막는다.
 *
 * 흐름
 *  1. 처음 보는 도구: 설명을 앙상블에 보내 검사한다. ALLOW면 해시를 고정(pin)하고 APPROVED, 아니면 QUARANTINED.
 *  2. 이미 고정된 도구: 설명 해시(옵션으로 코드 해시)가 달라졌으면 QUARANTINED로 바꾸고 호출을 막는다.
 *  3. 격리 해제: 변경된 해시에 묶인 승인 토큰으로만 가능하다(reapprove). 승인 토큰은 일회용이다.
 * 모든 상태 변화는 서명 원장에 기록한다. 고정 파일(tool-pins.tsv)은 재시작 사이에 상태를 이어 준다.
 */
@Service
public class ToolProvenanceService {
    public enum Status { APPROVED, QUARANTINED }

    public record ToolState(
            String name, String publisher, String pinnedDescriptionHash, String pinnedCodeHash,
            String currentDescriptionHash, String currentCodeHash, Status status, String reason) {
    }

    private final GroundTruthProperties properties;
    private final EnsembleService ensembleService;
    private final SignedAuditLedger ledger;
    private final ApprovalService approvalService;
    private final PermissionGraphService graphService;
    private final Path pinFile;
    private final Map<String, ToolState> tools = new LinkedHashMap<>();
    private final Map<String, String> descriptions = new LinkedHashMap<>();

    @Autowired
    public ToolProvenanceService(
            GroundTruthProperties properties,
            EnsembleService ensembleService,
            SignedAuditLedger ledger,
            ApprovalService approvalService,
            PermissionGraphService graphService,
            BuiltInToolCatalog catalog) {
        this.properties = properties;
        this.ensembleService = ensembleService;
        this.ledger = ledger;
        this.approvalService = approvalService;
        this.graphService = graphService;
        this.pinFile = Path.of(properties.toolPinFile()).toAbsolutePath().normalize();
        loadPins();
        for (ToolDescriptor descriptor : catalog.descriptors()) register(descriptor);
    }

    /* 도구를 등록하거나 다시 확인한다. 외부(서드파티) 도구도 같은 경로로 넣는다. */
    public synchronized ToolState register(ToolDescriptor descriptor) {
        String descriptionHash = sha256(normalize(descriptor.description()));
        String codeHash = descriptor.codeDigest() == null ? "" : descriptor.codeDigest();
        ToolState existing = tools.get(descriptor.name());
        descriptions.put(descriptor.name(), descriptor.description());
        ToolState next;
        if (existing == null || existing.pinnedDescriptionHash().isEmpty()) {
            next = firstSeen(descriptor, descriptionHash, codeHash);
        } else {
            boolean descriptionChanged = !existing.pinnedDescriptionHash().equals(descriptionHash);
            boolean codeChanged = !existing.pinnedCodeHash().isEmpty()
                    && !existing.pinnedCodeHash().equals(codeHash);
            boolean quarantine = descriptionChanged || (properties.pinCodeDigest() && codeChanged);
            if (quarantine) {
                String reason = (descriptionChanged ? "설명 해시 변경" : "코드 해시 변경")
                        + " (rug pull 의심). 재승인 전까지 호출을 막습니다.";
                next = new ToolState(descriptor.name(), descriptor.publisher(),
                        existing.pinnedDescriptionHash(), existing.pinnedCodeHash(),
                        descriptionHash, codeHash, Status.QUARANTINED, reason);
                if (existing.status() != Status.QUARANTINED
                        || !descriptionHash.equals(existing.currentDescriptionHash())) {
                    record("GT_TOOL_QUARANTINE", descriptor.name(), reason, descriptionHash, codeHash);
                }
            } else if (existing.status() == Status.QUARANTINED) {
                next = new ToolState(descriptor.name(), descriptor.publisher(),
                        existing.pinnedDescriptionHash(), existing.pinnedCodeHash(),
                        descriptionHash, codeHash, Status.QUARANTINED, existing.reason());
            } else {
                next = new ToolState(descriptor.name(), descriptor.publisher(),
                        existing.pinnedDescriptionHash(), codeChanged ? existing.pinnedCodeHash() : codeHash,
                        descriptionHash, codeHash, Status.APPROVED, "고정된 해시와 일치합니다.");
            }
        }
        tools.put(descriptor.name(), next);
        savePins();
        return next;
    }

    private ToolState firstSeen(ToolDescriptor descriptor, String descriptionHash, String codeHash) {
        boolean trusted = properties.trustedPublishers().contains(descriptor.publisher());
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("publisherTrusted", Boolean.toString(trusted));
        facts.put("descriptionChanged", "false");
        facts.put("codeChanged", "false");
        EnsembleVerdict verdict = ensembleService.assess(new EvidencePacket(
                "tool-registration", descriptor.name(), facts, List.of(descriptor.description())));
        if (verdict.verdict() == EnsembleVerdict.Verdict.ALLOW) {
            record("GT_TOOL_PIN", descriptor.name(), "최초 등록, 앙상블 통과", descriptionHash, codeHash);
            return new ToolState(descriptor.name(), descriptor.publisher(), descriptionHash, codeHash,
                    descriptionHash, codeHash, Status.APPROVED, verdict.rationale());
        }
        String reason = "등록 검사에서 " + verdict.verdict() + ": " + verdict.rationale();
        record("GT_TOOL_QUARANTINE", descriptor.name(), reason, descriptionHash, codeHash);
        return new ToolState(descriptor.name(), descriptor.publisher(), "", "",
                descriptionHash, codeHash, Status.QUARANTINED, reason);
    }

    public synchronized boolean isUsable(String name) {
        ToolState state = tools.get(name);
        return state != null && state.status() == Status.APPROVED;
    }

    public synchronized ToolState state(String name) {
        return tools.get(name);
    }

    public synchronized List<ToolState> states() {
        return new ArrayList<>(tools.values());
    }

    /* 격리된 도구를 다시 허용할 때 승인자가 서명하는 요청 해시다. 변경된 해시에 묶여 있어 다른 변경에는 쓸 수 없다. */
    public synchronized String reapprovalHash(String name) {
        ToolState state = require(name);
        return sha256("TOOL-REAPPROVE\n" + name + "\n" + state.currentDescriptionHash()
                + "\n" + state.currentCodeHash());
    }

    public synchronized ToolState reapprove(String name, ApprovalToken token, String actorDid) {
        ToolState state = require(name);
        if (state.status() != Status.QUARANTINED) return state;
        String description = descriptions.getOrDefault(name, "");
        EnsembleVerdict verdict = ensembleService.assess(new EvidencePacket(
                "tool-reapproval", name,
                Map.of("publisherTrusted", Boolean.toString(properties.trustedPublishers().contains(state.publisher())),
                        "descriptionChanged", "false", "codeChanged", "false"),
                List.of(description)));
        if (verdict.verdict() == EnsembleVerdict.Verdict.BLOCK) {
            throw new io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException(
                    "결정적 규칙에 걸리는 설명이라 승인으로도 허용할 수 없습니다: " + verdict.rationale());
        }
        approvalService.verifyAndConsume(token, reapprovalHash(name), actorDid, "tool:" + name);
        ToolState approved = new ToolState(name, state.publisher(),
                state.currentDescriptionHash(), state.currentCodeHash(),
                state.currentDescriptionHash(), state.currentCodeHash(), Status.APPROVED,
                "승인자 재승인: " + token.approverDid());
        tools.put(name, approved);
        record("GT_TOOL_REAPPROVE", name, approved.reason(),
                approved.currentDescriptionHash(), approved.currentCodeHash());
        savePins();
        return approved;
    }

    /* 이 도구를 호출할 수 있는 에이전트와, 그 에이전트가 다시 위임한 하위 에이전트 전체. */
    public synchronized Set<String> blastRadius(String name, Instant now) {
        Set<String> direct = graphService.agentsWithAccess(name, null, now);
        Set<String> all = new java.util.TreeSet<>(direct);
        for (String agent : direct) all.addAll(graphService.downstreamAgents(agent));
        return all;
    }

    private ToolState require(String name) {
        ToolState state = tools.get(name);
        if (state == null) throw new IllegalArgumentException("등록되지 않은 도구입니다: " + name);
        return state;
    }

    private void record(String action, String name, String reason, String descriptionHash, String codeHash) {
        ledger.append("tool-" + Instant.now().toEpochMilli(), "gateway", action, name,
                "RECORD", reason, descriptionHash, codeHash);
    }

    private void loadPins() {
        if (!Files.exists(pinFile)) return;
        try {
            for (String line : Files.readAllLines(pinFile, StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                String[] parts = line.split("\t", -1);
                if (parts.length != 7) throw new IllegalStateException("고정 파일 형식 오류");
                String name = unb64(parts[0]);
                tools.put(name, new ToolState(name, unb64(parts[1]), parts[2], parts[3], parts[4], parts[5],
                        Status.valueOf(parts[6]), "고정 파일에서 복원"));
            }
        } catch (IOException | RuntimeException exception) {
            throw new IllegalStateException("도구 고정 파일을 읽지 못했습니다: " + pinFile, exception);
        }
    }

    private void savePins() {
        try {
            Path parent = pinFile.getParent();
            if (parent != null) Files.createDirectories(parent);
            List<String> lines = new ArrayList<>();
            for (ToolState state : tools.values()) {
                lines.add(String.join("\t", b64(state.name()), b64(state.publisher()),
                        state.pinnedDescriptionHash(), state.pinnedCodeHash(),
                        state.currentDescriptionHash(), state.currentCodeHash(), state.status().name()));
            }
            Path temporary = pinFile.resolveSibling(pinFile.getFileName() + ".tmp");
            Files.write(temporary, lines, StandardCharsets.UTF_8);
            Files.move(temporary, pinFile, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException exception) {
            throw new IllegalStateException("도구 고정 파일을 저장하지 못했습니다: " + pinFile, exception);
        }
    }

    static String normalize(String text) {
        return Normalizer.normalize(text == null ? "" : text, Normalizer.Form.NFKC).strip();
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256을 사용할 수 없습니다.", exception);
        }
    }

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String unb64(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }
}
