# Passerelle de pseudonymisation chiffrée (Rust)

Protège les données sensibles **avant** qu'elles ne partent vers un LLM cloud
(OpenAI, Anthropic…), tout en gardant le RAG fonctionnel. La passerelle remplace
chaque donnée sensible par un jeton réversible, chiffre la valeur réelle en
**AES-256-GCM**, et restitue les vraies valeurs sur le chemin retour.

> **Pourquoi pas chiffrer tout le document ?**
> AES produit du texte aléatoire ; un modèle d'embedding a besoin du sens du
> texte pour produire un vecteur utile. On ne chiffre donc que les **éléments
> sensibles** (noms, emails, IBAN…), et on laisse le reste lisible pour que la
> recherche RAG fonctionne. C'est de la **dé-identification ciblée**, pas du
> chiffrement intégral.

## Place dans l'architecture

```
Spring AI RAG ──► /pseudonymize ──► texte « propre » ──► LLM cloud (embeddings / génération)
                      (Rust)                                      │
Spring AI RAG ◄── /depseudonymize ◄── réponse avec jetons ◄───────┘
                      (Rust)
```

Le LLM ne voit jamais les identifiants en clair. Seul le coffre (en mémoire ici)
détient la correspondance `jeton ↔ valeur réelle`, chiffrée en AES-256-GCM.

## Lancer

Pré-requis : [Rust stable](https://rustup.rs) (`cargo`).

```bash
# 1. Générer une clé maître (32 octets hex) et la placer dans l'environnement
export MASTER_KEY=$(openssl rand -hex 32)

# 2. Démarrer le service (port 8080)
cargo run
```

Sans `MASTER_KEY`, une clé de DEV éphémère est générée (un avertissement
s'affiche) — pratique pour tester, à NE PAS utiliser en production.

### Avec coffre Redis (persistant)

```bash
# 1. Démarrer Redis (persistance AOF + volume)
docker compose up -d

# 2. Lancer la passerelle en mode Redis
export MASTER_KEY=$(openssl rand -hex 32)
export VAULT_STORE=redis
export REDIS_URL=redis://127.0.0.1:6379
cargo run

# 3. Valider le round-trip Redis (test d'intégration, Redis requis)
cargo test -- --ignored
```

**Preuve de persistance** : créez un jeton via `POST /pseudonymize`, arrêtez puis
relancez le service (`cargo run`), et `POST /depseudonymize` du même jeton restitue
toujours la valeur — la correspondance vit dans Redis, plus en mémoire.

## Tester

Dans un autre terminal :

```bash
./test.sh
```

ou manuellement :

```bash
curl -X POST http://localhost:8080/pseudonymize \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "JohnTech a signe un contrat avec Marie Dupont (marie.dupont@gmail.com), IBAN FR76 3000 1007 9412.",
    "custom_terms": [
      {"type": "ORG", "value": "JohnTech"},
      {"type": "PERSON", "value": "Marie Dupont"}
    ]
  }'
```

Réponse attendue (le `text` est ce que vous envoyez au LLM) :

```json
{
  "text": "[ORG_1] a signe un contrat avec [PERSON_1] ([EMAIL_1]), IBAN [IBAN_1].",
  "tokens": ["ORG_1", "PERSON_1", "EMAIL_1", "IBAN_1"]
}
```

Puis, pour restituer les vraies valeurs d'une réponse du LLM :

```bash
curl -X POST http://localhost:8080/depseudonymize \
  -H 'Content-Type: application/json' \
  -d '{"text": "Le client est [PERSON_1], joignable a [EMAIL_1]."}'
# -> { "text": "Le client est Marie Dupont, joignable a marie.dupont@gmail.com." }
```

## Contrats des endpoints

### `POST /pseudonymize`
| Champ | Type | Description |
|---|---|---|
| `text` | string | Texte à protéger |
| `custom_terms` | array (optionnel) | Termes nommés que la regex ne détecte pas : `{ "type": "PERSON", "value": "Marie Dupont" }` |

Renvoie `{ "text": "...jetons...", "tokens": [...] }`.

### `POST /depseudonymize`
| Champ | Type | Description |
|---|---|---|
| `text` | string | Texte contenant des jetons `[TYPE_N]` |

Renvoie `{ "text": "...valeurs réelles..." }`.

## Données détectées automatiquement

Deux niveaux de détection :

1. **Regex** (intégré) : EMAIL, IBAN, CARD (carte 16 chiffres), PHONE (format FR).
2. **NER Presidio** (optionnel) : PERSON, ORG, LOCATION… détectés automatiquement
   si le service Presidio tourne (voir `integrations/ner/`). Lancez-le avec
   `docker compose up -d`. Si Presidio est indisponible, la passerelle continue
   sans erreur (regex + `custom_terms` seulement).

Avec Presidio actif, les `custom_terms` deviennent **optionnels** : plus besoin de
lister les noms à la main. Variables d'environnement : `PRESIDIO_URL`
(défaut `http://127.0.0.1:5002`), `PRESIDIO_LANG` (défaut `en` ; `fr` requiert
le modèle français, voir `integrations/ner/`).

## Schéma de clés

- Clé maître AES-256 = 32 octets, fournie via `MASTER_KEY` (hex).
- Un **nonce de 96 bits neuf par valeur** chiffrée (jamais réutilisé).
- Blob stocké = `nonce(12) || ciphertext` ; GCM garantit aussi l'intégrité.
- Production : clé dans **Vault / KMS**, rotation périodique, coffre dans un store
  persistant chiffré (Redis/Postgres) plutôt qu'en mémoire.

## Intégration Spring AI

Le plus propre : un `Advisor` Spring AI qui appelle `/pseudonymize` avant l'envoi
au modèle et `/depseudonymize` après réception. La logique crypto reste isolée
en Rust ; Spring AI ne voit qu'un point d'entrée.

## Limite à assumer

La pseudonymisation **n'est pas** une confidentialité totale : le contenu non
sensible part quand même dans le cloud, et un texte très contextuel peut parfois
être ré-identifié. Pour une exigence légale forte, complétez par un contrat (DPA)
avec le fournisseur. La seule confidentialité **totale** passe par des modèles
hébergés localement (ce qui nécessite un GPU).

## Aller plus loin

- **Détection de noms/lieux automatique** : brancher un service NER (ex. Presidio,
  spaCy) appelé depuis la passerelle, au lieu des `custom_terms`.
- **Cohérence inter-documents** : remplacer le coffre en mémoire par un store
  partagé pour que `[PERSON_1]` désigne la même personne d'une requête à l'autre.
- **Sessions** : ajouter un `session_id` pour cloisonner les espaces de jetons.

## Architecture interne (refonte production-ready)

La persistance du coffre est isolée derrière un trait **`VaultStore`** (mémoire
aujourd'hui, Redis/Postgres demain) : le store ne voit **jamais** le clair, seulement
des octets chiffrés et des **index aveugles**.

- **Blind index** : la déduplication (« même valeur → même jeton ») se fait via
  `HMAC-SHA256(index_key, tenant ‖ type ‖ valeur)`, et non plus en stockant la valeur
  en clair comme clé. Le `tenant` dans l'entrée empêche toute corrélation entre clients.
- **Blob auto-descriptif** : chaque valeur chiffrée est stockée sous la forme
  `key_id(4) ‖ nonce(12) ‖ ciphertext` → prépare la rotation de clé (Phase 4).
- **Isolation tenant** : champ `tenant_id` optionnel sur les 2 endpoints (défaut
  `_global`, rétro-compatible). Espaces de jetons disjoints, aucune restitution croisée.
- **Robustesse** : handlers `Result<_, AppError>` (plus de `.unwrap()`), logs `tracing`
  (jamais de valeur en clair), endpoint `GET /health`.

**Coffre persistant** : `VAULT_STORE=redis` bascule sur `RedisVaultStore` (création
de jeton atomique via script Lua, clés namespacées `pg:{tenant}:…`). Le jeton survit
alors aux redémarrages → `[PERSON_1]` reste stable entre l'ingestion et les requêtes.
Défaut `memory` (non persistant) pour le dev/tests.

Feuille de route restante : `KeyProvider` Vault/KMS + rotation (Phase 4),
remplacement par spans (Phase 5). Voir `PROMPT_CLAUDE_CODE.md`.

## Fichiers

```
pseudo-gateway/
├── Cargo.toml
├── .env.example
├── test.sh
├── README.md
└── src/
    ├── main.rs          # serveur axum + endpoints (+ /health, tenant_id)
    ├── crypto.rs        # chiffrement AES-256-GCM brut
    ├── keys.rs          # trousseau : chiffrement versionné + blind index HMAC
    ├── store.rs         # trait VaultStore + InMemoryVaultStore
    ├── error.rs         # AppError / VaultError -> réponses HTTP propres
    ├── ner.rs           # client NER Presidio (best effort)
    └── pseudonymize.rs  # détection + jetonnage (async, adossé au VaultStore)
```
