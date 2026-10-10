# Intégrations : clients prêts à l'emploi, NER automatique, Advisor Spring AI

## Clients

| Fichier | Dépendances | Pour |
|---|---|---|
| [`python/pseudo_gateway.py`](python/pseudo_gateway.py) | aucune (bibliothèque standard) | Python 3.10+ |
| [`java/PseudoGatewayClient.java`](java/PseudoGatewayClient.java) | aucune (JDK 11+) | Java, hors Spring |
| [`spring/PseudoGatewayClient.java`](spring/PseudoGatewayClient.java) | Spring 6+ | applications Spring |
| [`spring/PseudonymizationAdvisor.java`](spring/PseudonymizationAdvisor.java) | Spring AI 1.0+ | brancher la passerelle dans un `ChatClient` |

**Python**

```python
from pseudo_gateway import PseudoGateway

gw = PseudoGateway("https://votre-domaine", "pgw_votre_cle")

propre = gw.pseudonymize("Marie Dupont (marie@exemple.fr) a signé.")
reponse = appeler_votre_llm(propre.text)       # le LLM ne voit que des jetons
print(gw.depseudonymize(reponse))              # les vraies valeurs reviennent
```

**Java, sans dépendance**

```bash
javac PseudoGatewayClient.java
java PseudoGatewayClient https://votre-domaine pgw_votre_cle
```

### Trois choses à savoir avant de brancher

1. **La clé d'API est obligatoire**, dans l'en-tête `X-Api-Key` (ou
   `Authorization: Bearer`). Sans elle, tout repart en `401` : c'est l'oubli le
   plus fréquent. Demandez-la à l'exploitant de l'instance.
2. **Les jetons de la réponse n'ont pas de crochets.** `tokens` contient
   `EMAIL_1`, le texte contient `[EMAIL_1]`, et c'est cette forme-là qu'il faut
   renvoyer à `/v1/depseudonymize`. Les deux clients fournissent `bracketed`
   pour éviter l'erreur.
3. **Gérez le `429`.** Au-delà du quota ou de la limite par minute, la réponse
   porte un en-tête `Retry-After`. Le client Python patiente et réessaie ; en
   Java, `estLimite()` vous le signale.

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
