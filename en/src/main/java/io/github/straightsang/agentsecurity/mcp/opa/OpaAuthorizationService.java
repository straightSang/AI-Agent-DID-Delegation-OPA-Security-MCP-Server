package io.github.straightsang.agentsecurity.mcp.opa;

import io.github.straightsang.agentsecurity.mcp.approval.PolicyOutcome;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

/** Requests a policy decision from OPA and fails closed on errors. */
@Service
public class OpaAuthorizationService {
    private final RestClient restClient;

    public OpaAuthorizationService(RestClient.Builder builder, OpaProperties properties) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(properties.timeout());
        requestFactory.setReadTimeout(properties.timeout());
        this.restClient = builder
                .baseUrl(properties.url())
                .requestFactory(requestFactory)
                .build();
    }

    public OpaDecision authorize(OpaInput input) {
        try {
            OpaResponse response = restClient
                    .post()
                    .uri("/v1/data/agent/authz/decision")
                    .body(Map.of("input", input))
                    .retrieve()
                    .body(OpaResponse.class);

            if (response != null && response.result() != null) {
                return new OpaDecision(
                        PolicyOutcome.valueOf(response.result().outcome()),
                        response.result().reason(),
                        response.result().risks() == null ? List.of() : response.result().risks());
            }
            return OpaDecision.deny("OPA_DENY");
        } catch (RestClientException exception) {
            return OpaDecision.deny("OPA_UNAVAILABLE");
        }
    }

    private record OpaResponse(Result result) {
    }

    private record Result(String outcome, String reason, List<String> risks) {
    }
}
