# Prompt à coller dans Claude Code

> Copiez tout le bloc ci-dessous dans Claude Code, à la racine du projet `pseudo-gateway`.

---

## Contexte

Je développe une **passerelle de pseudonymisation chiffrée** en Rust qui s'insère
entre une application **Spring AI RAG** et un **LLM cloud** (OpenAI / Anthropic).
But : protéger les données sensibles avant qu'elles ne partent dans le cloud, tout
en gardant le RAG fonctionnel.

Principe : on ne chiffre pas tout le texte (sinon l'embedding est inutile). On
remplace seulement les **données sensibles** par des jetons réversibles `[TYPE_N]`,
on chiffre la valeur réelle en **AES-256-GCM**, on envoie le texte « propre » au LLM,
et on restitue les vraies valeurs sur le chemin retour.

C'est une **dé-identification** vis-à-vis du cloud, PAS une confidentialité totale
(impossible sans modèles locaux, et je n'ai pas de GPU).

## État actuel du projet (déjà fonctionnel)

- `src/main.rs` — serveur axum, endpoints `POST /pseudonymize` et `POST /depseudonymize`.
- `src/crypto.rs` — chiffrement AES-256-GCM (nonce 96 bits par valeur).
- `src/pseudonymize.rs` — détection regex (EMAIL, IBAN, CARD, PHONE) + jetonnage +
  coffre en mémoire (`HashMap`).
- `src/ner.rs` — client du service NER **Microsoft Presidio** (détecte PERSON, ORG,
  LOCATION…), appelé par `/pseudonymize`.
- `integrations/spring/` — `PseudoGatewayClient.java` + `PseudonymizationAdvisor.java`
  (Advisor Spring AI 1.0+, méthodes `before`/`after`).
- `integrations/ner/docker-compose.yml` — lance Presidio.

Le coffre actuel est **en mémoire** (perdu au redémarrage) et la clé vient d'une
variable d'environnement `MASTER_KEY`.

## Objectif

Faire évoluer ce prototype vers une version **production-ready**, en gardant l'API
HTTP existante compatible.

## Tâches, par ordre de priorité

1. **Coffre persistant et partagé.** Remplacer le `HashMap` en mémoire par un store
   persistant (commence par **Redis**, derrière un trait `VaultStore` pour pouvoir
   brancher Postgres ensuite). Indispensable pour que `[PERSON_1]` désigne la même
   personne entre l'ingestion des documents et les requêtes, et survive aux
   redémarrages. Garde la valeur **chiffrée** dans le store (jamais en clair).

2. **Gestion de clés via KMS/Vault.** Charger la clé maître depuis HashiCorp Vault
   (ou un KMS), pas depuis l'environnement. Prévoir la **rotation de clé** (versionner
   les entrées chiffrées avec un identifiant de clé).

3. **Cloisonnement par session/tenant.** Ajouter un `session_id` (ou `tenant_id`)
   optionnel aux requêtes pour isoler les espaces de jetons entre clients/documents.

4. **Robustesse.** Gestion d'erreurs propre (pas de `.unwrap()` dans les handlers),
   codes HTTP corrects, timeouts sur l'appel Presidio, logs structurés (`tracing`).

5. **Tests.** Tests unitaires sur le round-trip pseudonymize → depseudonymize (dont
   texte accentué français), et un test d'intégration des endpoints.

## Contraintes

- Garder le code Rust idiomatique, async (tokio), et qui compile sur stable.
- Ne pas tenir de valeurs sensibles en clair plus longtemps que nécessaire.
- L'appel réseau à Presidio doit rester **best effort** (si indisponible, continuer
  avec regex + termes manuels, sans planter).
- Documenter chaque changement dans le `README.md`.

## Critères de validation

- `cargo build` et `cargo test` passent.
- En arrêtant puis relançant le service, un jeton créé avant le redémarrage est
  toujours déchiffrable (preuve de la persistance).
- Un `POST /pseudonymize` sur du texte français accentué jetonne correctement et le
  `/depseudonymize` restitue exactement l'original.

Commence par me proposer un plan (architecture du trait `VaultStore`, schéma des
données Redis, gestion de la rotation de clé) avant d'écrire le code.
