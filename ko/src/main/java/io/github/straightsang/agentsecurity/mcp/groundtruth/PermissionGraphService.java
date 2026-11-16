package io.github.straightsang.agentsecurity.mcp.groundtruth;

import io.github.straightsang.agentsecurity.mcp.audit.SignedAuditEvent;
import io.github.straightsang.agentsecurity.mcp.audit.SignedAuditLedger;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationProperties;
import io.github.straightsang.agentsecurity.mcp.delegation.DelegationRevocationService;
import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/*
 * 권한 그래프를 서명 원장에서 다시 만들어 내는(event sourcing) 서비스다.
 *
 * 그래프의 원본은 서명된 감사 원장이다. 메모리의 그래프는 원장에서 계산한 결과일 뿐이라서
 * 서버를 재시작해도 원장만 있으면 같은 그래프가 복원되고, 그래프를 몰래 고쳐도 원장과 대조하면 드러난다.
 *
 * 원장에 남기는 이벤트
 *   GT_DELEGATION: resource = tokenId, reason = 토큰 필드를 인코딩한 문자열 (Gateway가 검증을 통과시킨 토큰만 기록)
 *   GT_REVOCATION: resource = tokenId
 * 서명 값은 원장에 넣지 않는다. 원장 이벤트 자체가 Gateway 서명이기 때문이다.
 */
@Service
public class PermissionGraphService {
    public static final String ACTION_DELEGATION = "GT_DELEGATION";
    public static final String ACTION_REVOCATION = "GT_REVOCATION";
    private static final String SYSTEM_ACTOR = "gateway";

    private final SignedAuditLedger ledger;
    private final DelegationProperties delegationProperties;
    private final DelegationRevocationService revocationService;
    private final GroundTruthProperties properties;
    private PermissionGraph graph = new PermissionGraph();

    @Autowired
    public PermissionGraphService(
            SignedAuditLedger ledger,
            DelegationProperties delegationProperties,
            DelegationRevocationService revocationService,
            GroundTruthProperties properties) {
        this.ledger = ledger;
        this.delegationProperties = delegationProperties;
        this.revocationService = revocationService;
        this.properties = properties;
        rebuild();
    }

    /* 원장 전체를 처음부터 다시 읽어 그래프를 새로 만든다. */
    public synchronized int rebuild() {
        PermissionGraph rebuilt = new PermissionGraph();
        int applied = 0;
        for (SignedAuditEvent event : ledger.snapshot()) {
            if (ACTION_DELEGATION.equals(event.action())) {
                rebuilt.addToken(decodeToken(event.resource(), event.reason()));
                applied++;
            } else if (ACTION_REVOCATION.equals(event.action())) {
                rebuilt.revoke(event.resource());
                applied++;
            }
        }
        this.graph = rebuilt;
        return applied;
    }

    /*
     * 검증을 통과한 위임 체인을 그래프에 반영한다. 처음 보는 토큰만 원장에 기록하고 새로 추가된 tokenId를 돌려준다.
     * 호출자는 DelegationVerifier 검증이 끝난 체인만 넘겨야 한다.
     */
    public synchronized List<String> ingestChain(List<DelegationToken> chain, String requestId) {
        List<String> added = new ArrayList<>();
        for (DelegationToken token : chain) {
            if (graph.token(token.tokenId()) != null) continue;
            PermissionGraph.TokenNode node = PermissionGraph.TokenNode.from(token);
            ledger.append(requestId, SYSTEM_ACTOR, ACTION_DELEGATION, token.tokenId(),
                    "RECORD", encodeToken(node), "", "");
            graph.addToken(node);
            added.add(token.tokenId());
        }
        return added;
    }

    /* 토큰과, 이 토큰을 부모로 삼은 모든 하위 토큰을 폐기한다. 폐기한 tokenId 목록을 돌려준다. */
    public synchronized List<String> revokeCascade(String tokenId, String requestId, String reason) {
        Set<String> targets = new LinkedHashSet<>();
        targets.add(tokenId);
        boolean grew = true;
        while (grew) {
            grew = false;
            for (PermissionGraph.TokenNode node : graph.tokens()) {
                if (node.parentTokenId() != null && targets.contains(node.parentTokenId())
                        && targets.add(node.tokenId())) {
                    grew = true;
                }
            }
        }
        List<String> revokedNow = new ArrayList<>();
        for (String target : targets) {
            if (!graph.isRevoked(target)) {
                ledger.append(requestId, SYSTEM_ACTOR, ACTION_REVOCATION, target,
                        "RECORD", reason == null ? "" : reason, "", "");
                graph.revoke(target);
                revokedNow.add(target);
            }
            revocationService.revoke(target);
        }
        return revokedNow;
    }

    public synchronized List<PermissionGraph.Finding> findingsForChain(
            List<DelegationToken> chain, Instant now) {
        List<String> ids = chain.stream().map(DelegationToken::tokenId).toList();
        return graph.findings(properties, delegationProperties.trustedIssuers(), ids, now);
    }

    public synchronized List<PermissionGraph.Finding> allFindings(Instant now) {
        return graph.findings(properties, delegationProperties.trustedIssuers(), null, now);
    }

    public synchronized List<PermissionGraph.EffectiveGrant> effectiveGrants(String agentDid, Instant now) {
        return graph.effectiveGrants(agentDid, now);
    }

    public synchronized Set<String> agentsWithAccess(String action, String resource, Instant now) {
        return graph.agentsWithAccess(action, resource, now);
    }

    public synchronized Set<String> downstreamAgents(String agentDid) {
        return graph.downstreamAgents(agentDid);
    }

    public synchronized Set<String> agents() {
        return new TreeSet<>(graph.agents());
    }

    /* 메모리 그래프가 서명 원장에서 다시 계산한 그래프와 같은지 비교한다. 다르면 메모리나 원장이 변조된 것이다. */
    public synchronized boolean matchesLedger() {
        PermissionGraph fresh = new PermissionGraph();
        for (SignedAuditEvent event : ledger.snapshot()) {
            if (ACTION_DELEGATION.equals(event.action())) {
                fresh.addToken(decodeToken(event.resource(), event.reason()));
            } else if (ACTION_REVOCATION.equals(event.action())) {
                fresh.revoke(event.resource());
            }
        }
        return fresh.tokens().equals(graph.tokens()) && fresh.revokedTokenIds().equals(graph.revokedTokenIds());
    }

    public synchronized int tokenCount() {
        return graph.tokens().size();
    }

    public synchronized List<PermissionGraph.TokenNode> tokens() {
        return new ArrayList<>(graph.tokens());
    }

    public synchronized boolean isRevoked(String tokenId) {
        return graph.isRevoked(tokenId);
    }

    public synchronized PermissionGraph.TokenNode token(String tokenId) {
        return graph.token(tokenId);
    }

    /* 필드 구분은 탭, 각 값은 base64url, 집합은 쉼표로 이은 base64url 항목이다. */
    static String encodeToken(PermissionGraph.TokenNode node) {
        return String.join("\t",
                b64(node.parentTokenId() == null ? "" : node.parentTokenId()),
                b64(node.issuer()), b64(node.subject()), b64(node.audience()),
                encodeSet(node.actions()), encodeSet(node.resources()),
                node.issuedAt().toString(), node.expiresAt().toString(),
                Integer.toString(node.depth()));
    }

    static PermissionGraph.TokenNode decodeToken(String tokenId, String encoded) {
        String[] parts = encoded.split("\t", -1);
        if (parts.length != 9) {
            throw new IllegalStateException("권한 그래프 이벤트 형식이 올바르지 않습니다: " + tokenId);
        }
        String parent = unb64(parts[0]);
        return new PermissionGraph.TokenNode(
                tokenId, parent.isEmpty() ? null : parent,
                unb64(parts[1]), unb64(parts[2]), unb64(parts[3]),
                decodeSet(parts[4]), decodeSet(parts[5]),
                Instant.parse(parts[6]), Instant.parse(parts[7]), Integer.parseInt(parts[8]));
    }

    private static String encodeSet(Set<String> values) {
        return String.join(",", new TreeSet<>(values).stream().map(PermissionGraphService::b64).toList());
    }

    private static Set<String> decodeSet(String encoded) {
        Set<String> result = new TreeSet<>();
        if (encoded.isEmpty()) return Set.copyOf(result);
        for (String item : encoded.split(",")) result.add(unb64(item));
        return Set.copyOf(result);
    }

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String unb64(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }
}
