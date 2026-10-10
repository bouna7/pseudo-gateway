import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Client Java pour la passerelle de pseudonymisation, <b>sans aucune dépendance</b>
 * (JDK 11+). Pour Spring, voir {@code integrations/spring}.
 *
 * <p>Démonstration :
 * <pre>
 * javac PseudoGatewayClient.java
 * java PseudoGatewayClient https://votre-domaine pgw_votre_cle
 * </pre>
 */
public class PseudoGatewayClient {

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private final String baseUrl;
    private final String apiKey;
    private final String tenantId;

    public PseudoGatewayClient(String baseUrl, String apiKey) {
        this(baseUrl, apiKey, null);
    }

    /** {@code tenantId} cloisonne les jetons à l'intérieur du compte (par dossier, par client). */
    public PseudoGatewayClient(String baseUrl, String apiKey, String tenantId) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.apiKey = apiKey;
        this.tenantId = tenantId;
    }

    /**
     * Texte prêt pour le LLM et jetons qu'il contient.
     *
     * <p>{@code tokens} les liste <b>sans crochets</b> ({@code EMAIL_1}) alors que le
     * texte les écrit {@code [EMAIL_1]} : {@link #bracketed()} donne la forme à
     * renvoyer à {@link #depseudonymize}.
     */
    public record PseudoResponse(String text, List<String> tokens) {
        public List<String> bracketed() {
            return tokens.stream().map(t -> "[" + t + "]").toList();
        }
    }

    /** Erreur renvoyée par la passerelle. {@code code} est stable, {@code message} est pour l'humain. */
    public static class GatewayException extends RuntimeException {
        public final int status;
        public final String code;

        GatewayException(int status, String code, String message) {
            super("[" + status + " " + code + "] " + message);
            this.status = status;
            this.code = code;
        }

        /** Quota mensuel ou limite par minute atteints : réessayer plus tard. */
        public boolean estLimite() {
            return status == 429;
        }
    }

    public PseudoResponse pseudonymize(String texte) {
        String corps = "{\"text\":" + quote(texte) + tenant() + "}";
        String json = post("/v1/pseudonymize", corps);
        return new PseudoResponse(champ(json, "text"), tableau(json, "tokens"));
    }

    /** Restitue les valeurs réelles. Un jeton inconnu est laissé tel quel. */
    public String depseudonymize(String texteAvecJetons) {
        String corps = "{\"text\":" + quote(texteAvecJetons) + tenant() + "}";
        return champ(post("/v1/depseudonymize", corps), "text");
    }

    private String tenant() {
        return tenantId == null ? "" : ",\"tenant_id\":" + quote(tenantId);
    }

    private String post(String chemin, String corpsJson) {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + chemin))
                // Sans cet en-tête, tout repart en 401 : l'oubli le plus fréquent.
                .header("X-Api-Key", apiKey)
                // charset=utf-8 : JSON impose cet encodage, et la passerelle refuse le reste.
                .header("Content-Type", "application/json; charset=utf-8")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(corpsJson, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (java.io.IOException | InterruptedException e) {
            throw new RuntimeException("passerelle injoignable : " + e.getMessage(), e);
        }
        if (res.statusCode() >= 400) {
            throw new GatewayException(res.statusCode(), champ(res.body(), "error"), champ(res.body(), "message"));
        }
        return res.body();
    }

    // ─── Lecture JSON minimale ───────────────────────────────────────────────
    // Volontairement réduite aux deux réponses de cette API, pour garder le
    // fichier sans dépendance. Dans une vraie application, utilisez Jackson ou
    // Gson plutôt que ces deux méthodes.

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
                }
            }
        }
        return b.append('"').toString();
    }

    private static String champ(String json, String nom) {
        int i = json.indexOf("\"" + nom + "\"");
        if (i < 0) return "";
        int debut = json.indexOf('"', json.indexOf(':', i) ) + 1;
        StringBuilder b = new StringBuilder();
        for (int p = debut; p < json.length(); p++) {
            char c = json.charAt(p);
            if (c == '\\') {
                char suivant = json.charAt(++p);
                switch (suivant) {
                    case 'n' -> b.append('\n');
                    case 't' -> b.append('\t');
                    case 'r' -> b.append('\r');
                    case 'u' -> {
                        b.append((char) Integer.parseInt(json.substring(p + 1, p + 5), 16));
                        p += 4;
                    }
                    default -> b.append(suivant);
                }
            } else if (c == '"') {
                break;
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    private static List<String> tableau(String json, String nom) {
        List<String> out = new ArrayList<>();
        int i = json.indexOf("\"" + nom + "\"");
        if (i < 0) return out;
        int debut = json.indexOf('[', i);
        int fin = json.indexOf(']', debut);
        if (debut < 0 || fin < 0) return out;
        for (String brut : json.substring(debut + 1, fin).split(",")) {
            String v = brut.trim().replaceAll("^\"|\"$", "");
            if (!v.isEmpty()) out.add(v);
        }
        return out;
    }

    // ─── Démonstration ───────────────────────────────────────────────────────

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("usage : java PseudoGatewayClient <url> <cle pgw_...>");
            System.exit(2);
        }
        var gw = new PseudoGatewayClient(args[0], args[1], "dossier-demo");

        var propre = gw.pseudonymize("Marie Dupont (marie@exemple.fr, 06 11 22 33 44) a signé.");
        System.out.println("vers le LLM : " + propre.text());
        System.out.println("jetons      : " + propre.tokens() + "  dans le texte : " + propre.bracketed());

        String reponseDuLlm = "J'ai répondu à " + propre.bracketed().get(0) + " ce matin.";
        System.out.println("restitue    : " + gw.depseudonymize(reponseDuLlm));

        try {
            new PseudoGatewayClient(args[0], "pgw_inexistante").pseudonymize("test");
        } catch (GatewayException e) {
            System.out.println("mauvaise cle: code=" + e.code + " status=" + e.status);
        }
    }
}
