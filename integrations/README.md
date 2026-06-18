# Intégrations : NER automatique + Advisor Spring AI

## 1. NER automatique (Presidio)

La passerelle détecte par regex les données **à format strict** (email, IBAN,
carte, téléphone). Les **noms de personnes, organisations et lieux** demandent
un modèle ML : [Microsoft Presidio](https://microsoft.github.io/presidio/)
(basé sur spaCy) est le standard. Il n'existe pas d'équivalent Rust aussi mûr,
donc on le lance comme **microservice Python auto-hébergé**.

```
texte ─► Passerelle Rust ─┬─► regex (email, IBAN, …)
                          └─► Presidio /analyze ─► PERSON, ORG, LOCATION
                          puis : jetonnage + AES-256-GCM
```

Point clé de confidentialité : le texte en clair va à Presidio, mais Presidio
tourne **dans votre périmètre**, pas dans le cloud. Aucune fuite vers le LLM.

- `docker-compose.yml` : lance `presidio-analyzer` sur le port 5002.
- `ner_client.rs` : client Rust de référence + notes pour le câbler dans
  `/pseudonymize` (la détection devient asynchrone : appeler Presidio **avant**
  de prendre le verrou du coffre).

Français : l'image par défaut est en anglais ; pour le français, construire une
image Presidio avec le modèle `fr_core_news_lg` (doc « Customizing the NLP
engine »). En attendant, les `custom_terms` couvrent les noms FR.

## 2. Advisor Spring AI (API 1.0+)

Un `Advisor` s'insère dans la chaîne du `ChatClient` et transforme la requête
avant l'appel au modèle et la réponse après. On implémente `BaseAdvisor`
(méthodes `before` / `after`).

- `PseudoGatewayClient.java` : client HTTP (RestClient) vers la passerelle Rust.
- `PseudonymizationAdvisor.java` : `before` → `/pseudonymize` ; `after` → `/depseudonymize`.

Enregistrement :

```java
@Bean
ChatClient chatClient(ChatClient.Builder builder, PseudoGatewayClient gateway) {
    return builder
        .defaultAdvisors(
            new PseudonymizationAdvisor(gateway),     // ordre très prioritaire
            QuestionAnswerAdvisor.builder(vectorStore).build()  // RAG après
        )
        .build();
}
```

### Ordre + RAG : le point à ne pas rater

L'advisor de pseudonymisation doit s'exécuter **avant** l'advisor RAG sur la
requête, pour que l'embedding de la question parte déjà dé-identifié dans le
cloud (ordre = `HIGHEST_PRECEDENCE + 100`, plus prioritaire que le RAG).

Surtout : les **documents du vector store doivent avoir été pseudonymisés à
l'ingestion** (mêmes appels `/pseudonymize`). Sinon l'advisor RAG ré-injecte du
contexte contenant des données sensibles en clair dans le prompt envoyé au LLM —
et la protection saute. Donc on pseudonymise à **deux moments** :

1. **Ingestion** : chaque document → `/pseudonymize` → stocké (jetonné) + indexé.
2. **Requête** : la question → `/pseudonymize` (cet advisor) → LLM → réponse →
   `/depseudonymize` → utilisateur.

Le coffre AES doit être **partagé et persistant** entre ces deux moments pour que
`[PERSON_1]` désigne toujours la même personne (remplacer le `HashMap` en mémoire
par Redis/Postgres chiffré).

## Compatibilité de version

Code aligné sur l'API Advisor de **Spring AI 1.0+** (`CallAdvisor`,
`ChatClientRequest`/`ChatClientResponse`). Avant la 1.0 M3, l'API utilisait
`CallAroundAdvisor` et `AdvisedRequest`/`AdvisedResponse`. La reconstruction de
la réponse dans `after()` peut demander un petit ajustement de constructeur
selon votre version exacte.
