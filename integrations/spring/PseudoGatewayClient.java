package com.example.privacy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

/**
 * Client HTTP vers la passerelle de pseudonymisation.
 *
 * <p>Configuration dans {@code application.yml} :
 * <pre>
 * pseudo-gateway:
 *   url: https://votre-domaine
 *   api-key: ${PSEUDO_GATEWAY_API_KEY}   # jamais en clair dans le dépôt
 * </pre>
 */
@Component
public class PseudoGatewayClient {

    private final RestClient http;

    public PseudoGatewayClient(
            @Value("${pseudo-gateway.url:http://127.0.0.1:8080}") String baseUrl,
            @Value("${pseudo-gateway.api-key:}") String apiKey) {
        this.http = RestClient.builder()
                .baseUrl(baseUrl)
                // Sans cet en-tête, toute requête repart en 401 : c'est l'oubli
                // le plus fréquent au premier branchement.
                .defaultHeader("X-Api-Key", apiKey)
                .defaultStatusHandler(status -> status.isError(), (req, res) -> {
                    String corps = new String(res.getBody().readAllBytes());
                    // Le corps est toujours un JSON { "error": ..., "message": ... } :
                    // `error` est stable et testable, `message` explique à l'humain.
                    throw new PseudoGatewayException(res.getStatusCode().value(), corps);
                })
                .build();
    }

    /** Terme que la détection automatique ignore, par exemple un nom de société. */
    public record CustomTerm(String type, String value) {}

    /**
     * Texte prêt pour le LLM et jetons qu'il contient.
     *
     * <p>{@code tokens} liste les jetons <b>sans crochets</b> ({@code EMAIL_1}),
     * alors que le texte les écrit entre crochets ({@code [EMAIL_1]}) : c'est
     * cette forme qu'il faut renvoyer à {@link #depseudonymize}.
     */
    public record PseudoResponse(String text, List<String> tokens) {}

    private record DepseudoResponse(String text) {}

    /** Remplace les données sensibles par des jetons réversibles. */
    public PseudoResponse pseudonymize(String text, List<CustomTerm> terms, String tenantId) {
        Map<String, Object> corps = terms == null || terms.isEmpty()
                ? Map.of("text", text)
                : Map.of("text", text, "custom_terms", terms);
        if (tenantId != null) {
            corps = new java.util.HashMap<>(corps);
            corps.put("tenant_id", tenantId);
        }
        return http.post().uri("/v1/pseudonymize").body(corps).retrieve().body(PseudoResponse.class);
    }

    public PseudoResponse pseudonymize(String text) {
        return pseudonymize(text, List.of(), null);
    }

    /** Restitue les valeurs réelles. Un jeton inconnu est laissé tel quel. */
    public String depseudonymize(String text, String tenantId) {
        Map<String, Object> corps = tenantId == null
                ? Map.of("text", text)
                : Map.of("text", text, "tenant_id", tenantId);
        DepseudoResponse r =
                http.post().uri("/v1/depseudonymize").body(corps).retrieve().body(DepseudoResponse.class);
        return r.text();
    }

    public String depseudonymize(String text) {
        return depseudonymize(text, null);
    }

    /** Erreur renvoyée par la passerelle : 401 clé, 400 requête, 429 quota… */
    public static class PseudoGatewayException extends RuntimeException {
        private final int status;

        public PseudoGatewayException(int status, String corps) {
            super("pseudo-gateway " + status + " : " + corps);
            this.status = status;
        }

        public int status() {
            return status;
        }

        /** Vrai quand le quota ou la limite par minute est atteint : il faut réessayer plus tard. */
        public boolean estLimite() {
            return status == 429;
        }
    }
}
