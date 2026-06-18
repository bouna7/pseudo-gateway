package com.example.privacy;

import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.AdvisorChain;
import org.springframework.ai.chat.client.advisor.api.BaseAdvisor;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.core.Ordered;

import java.util.List;

/**
 * Advisor Spring AI (API 1.0+) qui pseudonymise la requête utilisateur AVANT
 * l'envoi au LLM cloud, puis dé-pseudonymise la réponse APRÈS réception.
 *
 * BaseAdvisor fournit l'enrobage : on n'implémente que before() et after().
 *
 * IMPORTANT (RAG) : placez cet advisor AVANT le QuestionAnswerAdvisor /
 * RetrievalAugmentationAdvisor (ordre plus prioritaire) pour que la requête
 * soit déjà pseudonymisée quand l'embedding de la question part dans le cloud.
 * Les documents du vector store doivent eux aussi avoir été pseudonymisés à
 * l'ingestion (même passerelle), sinon le contexte RAG ré-injecte des données
 * sensibles en clair dans le prompt.
 */
public class PseudonymizationAdvisor implements BaseAdvisor {

    private final PseudoGatewayClient gateway;
    private final int order;

    public PseudonymizationAdvisor(PseudoGatewayClient gateway) {
        // Très prioritaire : premier sur la requête, dernier sur la réponse.
        this(gateway, Ordered.HIGHEST_PRECEDENCE + 100);
    }

    public PseudonymizationAdvisor(PseudoGatewayClient gateway, int order) {
        this.gateway = gateway;
        this.order = order;
    }

    @Override
    public ChatClientRequest before(ChatClientRequest request, AdvisorChain chain) {
        String userText = request.prompt().getUserMessage().getText();
        // List.of() = pas de termes manuels : on s'appuie sur la détection de la passerelle
        // (regex + NER Presidio si vous l'avez branché).
        var resp = gateway.pseudonymize(userText, List.of());
        return request.mutate()
                .prompt(request.prompt().augmentUserMessage(resp.text()))
                .build();
    }

    @Override
    public ChatClientResponse after(ChatClientResponse response, AdvisorChain chain) {
        ChatResponse cr = response.chatResponse();
        if (cr == null || cr.getResult() == null) {
            return response;
        }
        String llmText = cr.getResult().getOutput().getText();
        String restored = gateway.depseudonymize(llmText);

        // Reconstruit la réponse avec le texte déchiffré.
        // NB : selon votre version exacte de Spring AI, les constructeurs de
        // ChatResponse / Generation peuvent légèrement différer — adaptez si besoin.
        ChatResponse rebuilt = new ChatResponse(
                List.of(new Generation(new AssistantMessage(restored))),
                cr.getMetadata());

        return response.mutate().chatResponse(rebuilt).build();
    }

    @Override
    public int getOrder() {
        return this.order;
    }

    @Override
    public String getName() {
        return "PseudonymizationAdvisor";
    }
}
