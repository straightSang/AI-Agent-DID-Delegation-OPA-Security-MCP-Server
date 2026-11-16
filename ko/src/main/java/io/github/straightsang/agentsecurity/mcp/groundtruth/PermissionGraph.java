package io.github.straightsang.agentsecurity.mcp.groundtruth;

import io.github.straightsang.agentsecurity.mcp.domain.DelegationToken;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/*
 * 위임 토큰으로 만든 권한 그래프다. 노드는 DID와 토큰, 간선은 "issuer가 subject에게 위임했다"이다.
 * Gateway의 검증 로직과 별개로 실효 권한을 다시 계산해서, 검증기에 버그가 있어도 이상 징후를 찾아낸다.
 * 스레드 안전하지 않으므로 PermissionGraphService가 동기화한다.
 */
public class PermissionGraph {
    private static final int MAX_CHAIN_STEPS = 64;

    public enum Severity { LOW, MEDIUM, HIGH }

    public record TokenNode(
            String tokenId, String parentTokenId, String issuer, String subject, String audience,
            Set<String> actions, Set<String> resources,
            Instant issuedAt, Instant expiresAt, int depth) {

        public static TokenNode from(DelegationToken token) {
            return new TokenNode(
                    token.tokenId(), token.parentTokenId(), token.issuer(), token.subject(),
                    token.audience(), Set.copyOf(token.actions()), Set.copyOf(token.resources()),
                    token.issuedAt(), token.expiresAt(), token.delegationDepth());
        }
    }

    /* 체인 전체를 따라 교집합으로 다시 계산한 에이전트의 실효 권한이다. */
    public record EffectiveGrant(
            String leafTokenId, String rootIssuer, String subject,
            Set<String> actions, Set<String> resources, Instant expiresAt,
            int depth, List<String> chainTokenIds) {
    }

    public record Finding(String type, Severity severity, String subject, String tokenId, String detail) {
    }

    private final Map<String, TokenNode> tokens = new LinkedHashMap<>();
    private final Set<String> revoked = new HashSet<>();

    /* 새 토큰이면 true. 이미 있는 tokenId는 덮어쓰지 않는다. */
    public boolean addToken(TokenNode node) {
        return tokens.putIfAbsent(node.tokenId(), node) == null;
    }

    public void revoke(String tokenId) {
        revoked.add(tokenId);
    }

    public boolean isRevoked(String tokenId) {
        return revoked.contains(tokenId);
    }

    public TokenNode token(String tokenId) {
        return tokens.get(tokenId);
    }

    public Collection<TokenNode> tokens() {
        return List.copyOf(tokens.values());
    }

    public Set<String> revokedTokenIds() {
        return Set.copyOf(revoked);
    }

    public Set<String> agents() {
        Set<String> result = new TreeSet<>();
        for (TokenNode node : tokens.values()) {
            result.add(node.issuer());
            result.add(node.subject());
        }
        return result;
    }

    /* 에이전트가 지금 실제로 행사할 수 있는 권한을 체인별로 계산한다. */
    public List<EffectiveGrant> effectiveGrants(String agentDid, Instant now) {
        List<EffectiveGrant> grants = new ArrayList<>();
        for (TokenNode leaf : tokens.values()) {
            if (!leaf.subject().equals(agentDid)) continue;
            EffectiveGrant grant = evaluateChain(leaf, now);
            if (grant != null) grants.add(grant);
        }
        grants.sort(Comparator.comparing(EffectiveGrant::leafTokenId));
        return grants;
    }

    public Set<String> reachableResources(String agentDid, Instant now) {
        Set<String> result = new TreeSet<>();
        effectiveGrants(agentDid, now).forEach(grant -> result.addAll(grant.resources()));
        return result;
    }

    /* 특정 행동과 리소스를 실제로 행사할 수 있는 에이전트 목록. */
    public Set<String> agentsWithAccess(String action, String resource, Instant now) {
        Set<String> result = new TreeSet<>();
        for (String agent : agents()) {
            for (EffectiveGrant grant : effectiveGrants(agent, now)) {
                boolean actionOk = action == null || grant.actions().contains(action);
                boolean resourceOk = resource == null || grant.resources().contains(resource);
                if (actionOk && resourceOk) result.add(agent);
            }
        }
        return result;
    }

    /* agentDid가 위임한 권한을 이어받은 모든 하위 에이전트(재위임 포함). */
    public Set<String> downstreamAgents(String agentDid) {
        Set<String> seen = new LinkedHashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(agentDid);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            for (TokenNode node : tokens.values()) {
                if (node.issuer().equals(current) && !revoked.contains(node.tokenId())
                        && !node.subject().equals(agentDid) && seen.add(node.subject())) {
                    queue.add(node.subject());
                }
            }
        }
        return seen;
    }

    /* 주어진 토큰들에 대한 이상 징후를 찾는다. tokenIds가 null이면 전체 그래프를 검사한다. */
    public List<Finding> findings(
            GroundTruthProperties properties, Set<String> trustedRoots,
            Collection<String> tokenIds, Instant now) {
        List<Finding> result = new ArrayList<>();
        Collection<String> targets = tokenIds == null ? new ArrayList<>(tokens.keySet()) : tokenIds;
        Map<String, Long> liveFanOut = liveTokensPerIssuer(now);
        for (String tokenId : targets) {
            TokenNode node = tokens.get(tokenId);
            if (node == null || revoked.contains(tokenId)) continue;
            checkNode(node, properties, trustedRoots, liveFanOut, result);
        }
        return result;
    }

    private void checkNode(
            TokenNode node, GroundTruthProperties properties, Set<String> trustedRoots,
            Map<String, Long> liveFanOut, List<Finding> out) {
        if (node.depth() > properties.maxDepth()) {
            out.add(finding("DEPTH_EXCEEDED", Severity.HIGH, node,
                    "위임 깊이 " + node.depth() + "이 허용치 " + properties.maxDepth() + "를 넘었습니다."));
        }
        if (node.parentTokenId() == null) {
            if (!trustedRoots.isEmpty() && !trustedRoots.contains(node.issuer())) {
                out.add(finding("UNTRUSTED_ROOT", Severity.HIGH, node,
                        "신뢰 목록에 없는 발급자가 root 토큰을 만들었습니다."));
            }
        } else {
            TokenNode parent = tokens.get(node.parentTokenId());
            if (parent == null) {
                out.add(finding("ORPHAN_TOKEN", Severity.HIGH, node,
                        "부모 토큰 " + node.parentTokenId() + "이 그래프에 없습니다."));
            } else {
                checkAgainstParent(node, parent, out);
            }
            if (hasParentCycle(node)) {
                out.add(finding("PARENT_CYCLE", Severity.HIGH, node, "부모 참조가 순환합니다."));
            }
        }
        if (node.issuer().equals(node.subject())) {
            out.add(finding("SELF_DELEGATION", Severity.MEDIUM, node, "자기 자신에게 위임했습니다."));
        }
        if (node.actions().contains("*") || node.resources().contains("*")) {
            out.add(finding("BROAD_SCOPE", Severity.MEDIUM, node, "와일드카드 권한이 포함되어 있습니다."));
        }
        for (String resource : node.resources()) {
            String lowered = resource.toLowerCase(Locale.ROOT);
            if (properties.sensitiveKeywords().stream().anyMatch(lowered::contains)) {
                out.add(finding("SENSITIVE_SCOPE", Severity.MEDIUM, node,
                        "민감해 보이는 리소스가 위임되었습니다: " + resource));
                break;
            }
        }
        Duration ttl = Duration.between(node.issuedAt(), node.expiresAt());
        if (ttl.compareTo(properties.maxTokenTtl()) > 0) {
            out.add(finding("LONG_LIVED", Severity.MEDIUM, node,
                    "유효시간 " + ttl.toMinutes() + "분이 허용치 " + properties.maxTokenTtl().toMinutes() + "분을 넘었습니다."));
        }
        long fanOut = liveFanOut.getOrDefault(node.issuer(), 0L);
        if (fanOut > properties.maxFanOut()) {
            out.add(finding("FAN_OUT", Severity.MEDIUM, node,
                    node.issuer() + "가 유효 토큰 " + fanOut + "개를 발급했습니다."));
        }
    }

    /* 검증기와 독립적으로 부모 대비 권한 확대를 다시 검사한다. 검증기 버그나 원장 변조를 잡는 용도다. */
    private void checkAgainstParent(TokenNode node, TokenNode parent, List<Finding> out) {
        List<String> problems = new ArrayList<>();
        if (!parent.actions().containsAll(node.actions())) problems.add("action 확대");
        if (!parent.resources().containsAll(node.resources())) problems.add("resource 확대");
        if (node.expiresAt().isAfter(parent.expiresAt())) problems.add("만료 시각 연장");
        if (!node.audience().equals(parent.audience())) problems.add("audience 변경");
        if (!node.issuer().equals(parent.subject())) problems.add("issuer와 부모 subject 불일치");
        if (node.depth() != parent.depth() + 1) problems.add("깊이 불연속");
        if (!problems.isEmpty()) {
            out.add(finding("ESCALATION", Severity.HIGH, node,
                    "부모 토큰보다 넓어졌습니다: " + String.join(", ", problems)));
        }
    }

    private boolean hasParentCycle(TokenNode start) {
        Set<String> seen = new HashSet<>();
        TokenNode current = start;
        for (int step = 0; step < MAX_CHAIN_STEPS && current != null; step++) {
            if (!seen.add(current.tokenId())) return true;
            current = current.parentTokenId() == null ? null : tokens.get(current.parentTokenId());
        }
        return false;
    }

    private Map<String, Long> liveTokensPerIssuer(Instant now) {
        Map<String, Long> counts = new HashMap<>();
        for (TokenNode node : tokens.values()) {
            if (!revoked.contains(node.tokenId()) && node.expiresAt().isAfter(now)) {
                counts.merge(node.issuer(), 1L, Long::sum);
            }
        }
        return counts;
    }

    private EffectiveGrant evaluateChain(TokenNode leaf, Instant now) {
        List<TokenNode> chain = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        TokenNode current = leaf;
        while (current != null) {
            if (!seen.add(current.tokenId()) || chain.size() >= MAX_CHAIN_STEPS) return null;
            if (revoked.contains(current.tokenId()) || !current.expiresAt().isAfter(now)) return null;
            chain.add(current);
            if (current.parentTokenId() == null) break;
            current = tokens.get(current.parentTokenId());
            if (current == null) return null;
        }
        Set<String> actions = new TreeSet<>(leaf.actions());
        Set<String> resources = new TreeSet<>(leaf.resources());
        Instant expiresAt = leaf.expiresAt();
        for (TokenNode node : chain) {
            actions.retainAll(node.actions());
            resources.retainAll(node.resources());
            if (node.expiresAt().isBefore(expiresAt)) expiresAt = node.expiresAt();
        }
        if (actions.isEmpty() || resources.isEmpty()) return null;
        List<String> ids = new ArrayList<>(chain.stream().map(TokenNode::tokenId).toList());
        java.util.Collections.reverse(ids);
        return new EffectiveGrant(
                leaf.tokenId(), chain.getLast().issuer(), leaf.subject(),
                Set.copyOf(actions), Set.copyOf(resources), expiresAt, leaf.depth(), List.copyOf(ids));
    }

    private Finding finding(String type, Severity severity, TokenNode node, String detail) {
        return new Finding(type, severity, node.subject(), node.tokenId(), detail);
    }
}
