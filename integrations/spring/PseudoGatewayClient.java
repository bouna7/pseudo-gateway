package com.example.privacy;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

/**
 * Petit client HTTP vers la passerelle de pseudonymisation Rust (port 8080).
 * Utilise RestClient (Spring 6+).
 */
@Component
public class PseudoGatewayClient {

    private final RestClient http;

    public PseudoGatewayClient() {
        // En prod : injecter l'URL via application.yml plutôt que la coder en dur.
        this.http = RestClient.create("http://127.0.0.1:8080");
    }

    /** Terme nommé à protéger explicitement (si vous n'utilisez pas le NER auto). */
    public record CustomTerm(String type, String value) {}

    public record PseudoResponse(String text, List<String> tokens) {}

    private record DepseudoResponse(String text) {}

    /** Remplace les données sensibles par des jetons. Renvoie le texte « propre ». */
    public PseudoResponse pseudonymize(String text, List<CustomTerm> terms) {
        return http.post()
                .uri("/pseudonymize")
                .body(Map.of("text", text, "custom_terms", terms))
                .retrieve()
                .body(PseudoResponse.class);
    }

    /** Restitue les valeurs réelles à partir d'un texte contenant des jetons. */
    public String depseudonymize(String text) {
        DepseudoResponse r = http.post()
                .uri("/depseudonymize")
                .body(Map.of("text", text))
                .retrieve()
                .body(DepseudoResponse.class);
        return r.text();
    }
}
