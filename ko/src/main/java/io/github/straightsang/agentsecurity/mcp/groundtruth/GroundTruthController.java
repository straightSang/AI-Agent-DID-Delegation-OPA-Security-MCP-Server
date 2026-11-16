package io.github.straightsang.agentsecurity.mcp.groundtruth;

import io.github.straightsang.agentsecurity.mcp.approval.ApprovalToken;
import io.github.straightsang.agentsecurity.mcp.exception.AccessDeniedException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/*
 * Ground Truth 조회와 조치 API다. 로컬 실습 프로필에서만 열린다.
 * 조회 API는 권한 구조를 그대로 보여 주므로 운영에서는 반드시 인증을 붙여야 한다(이 프로젝트에는 구현하지 않았다).
 * 조치 API(폐기, 도구 재승인)는 요청 자체가 서명이나 승인 토큰으로 인증된다.
 */
@RestController
@RequestMapping("/ground-truth")
@Profile("local")
public class GroundTruthController {
    private final PermissionGraphService graphService;
    private final ToolProvenanceService toolService;
    private final RevocationAdminService revocationAdminService;

    public GroundTruthController(
            PermissionGraphService graphService,
            ToolProvenanceService toolService,
            RevocationAdminService revocationAdminService) {
        this.graphService = graphService;
        this.toolService = toolService;
        this.revocationAdminService = revocationAdminService;
    }

    @GetMapping("/summary")
    public Map<String, Object> summary() {
        Instant now = Instant.now();
        return Map.of(
                "tokens", graphService.tokenCount(),
                "agents", graphService.agents(),
                "findings", graphService.allFindings(now),
                "tools", toolService.states());
    }

    @GetMapping("/agents/permissions")
    public List<PermissionGraph.EffectiveGrant> permissions(@RequestParam("did") String did) {
        return graphService.effectiveGrants(did, Instant.now());
    }

    @GetMapping("/who-can")
    public Set<String> whoCan(
            @RequestParam(value = "action", required = false) String action,
            @RequestParam(value = "resource", required = false) String resource) {
        return graphService.agentsWithAccess(action, resource, Instant.now());
    }

    @GetMapping("/findings")
    public List<PermissionGraph.Finding> findings() {
        return graphService.allFindings(Instant.now());
    }

    @GetMapping("/consistency")
    public Map<String, Object> consistency() {
        return Map.of("matchesLedger", graphService.matchesLedger());
    }

    @GetMapping("/tools")
    public List<ToolProvenanceService.ToolState> tools() {
        return toolService.states();
    }

    @GetMapping("/tools/{name}/blast-radius")
    public Set<String> blastRadius(@PathVariable("name") String name) {
        return toolService.blastRadius(name, Instant.now());
    }

    @GetMapping("/tools/{name}/reapproval-hash")
    public Map<String, String> reapprovalHash(@PathVariable("name") String name) {
        return Map.of("requestHash", toolService.reapprovalHash(name), "target", "tool:" + name);
    }

    @PostMapping("/tools/{name}/reapprove")
    public ResponseEntity<?> reapprove(@PathVariable("name") String name, @RequestBody ReapproveRequest request) {
        try {
            return ResponseEntity.ok(toolService.reapprove(name, request.approvalToken(), request.actorDid()));
        } catch (AccessDeniedException exception) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", exception.getMessage()));
        }
    }

    @PostMapping("/revocations")
    public ResponseEntity<?> revoke(@RequestBody RevokeRequest request) {
        try {
            List<String> revoked = revocationAdminService.revoke(
                    request.tokenId(), request.requesterDid(), request.requestedAt(), request.signature());
            return ResponseEntity.ok(Map.of("revoked", revoked));
        } catch (AccessDeniedException exception) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", exception.getMessage()));
        }
    }

    public record ReapproveRequest(ApprovalToken approvalToken, String actorDid) {
    }

    public record RevokeRequest(String tokenId, String requesterDid, Instant requestedAt, String signature) {
    }
}
