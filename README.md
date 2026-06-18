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

- Clés AES-256 = 32 octets hex. Mode versionné `PSEUDO_KEY_<id>` (rotation), ou
  `MASTER_KEY` unique en repli ; chargées par un `KeyProvider` (Env → Vault/KMS demain).
- Un **nonce de 96 bits neuf par valeur** chiffrée (jamais réutilisé).
- Blob stocké = `key_id(4) || nonce(12) || ciphertext` ; le `key_id` rend le blob
  auto-descriptif (rotation sans réchiffrement) et GCM garantit l'intégrité.
- **Rotation** : ajouter `PSEUDO_KEY_<n+1>`, passer `PSEUDO_CURRENT_KEY_ID=<n+1>`,
  redémarrer. Les nouveaux blobs utilisent la nouvelle clé ; les anciens restent
  déchiffrables tant que leur version est présente. La clé d'index (`PSEUDO_INDEX_KEY`)
  reste **stable** sinon la déduplication casse.
- Coffre persistant chiffré : **Redis** (`VAULT_STORE=redis`), Postgres possible plus tard.

## Déploiement (Docker / Dokploy)

Image construite par le `Dockerfile` (build Rust release multi-stage → image
`debian-slim` **non-root**, port 8080).

```bash
docker build -t pseudo-gateway .
docker run -p 8080:8080 \
  -e VAULT_STORE=redis -e REDIS_URL=redis://redis:6379 \
  -e PSEUDO_KEY_1=<hex64> -e PSEUDO_INDEX_KEY=<hex64> \
  -e GATEWAY_API_KEY=<secret> \
  pseudo-gateway
```

### Sur Dokploy → `apirag.roostdrive.com`

1. **Application** dont la source est ce dépôt (build par le `Dockerfile`).
2. **Domaine** `apirag.roostdrive.com` → port conteneur **8080**, HTTPS. Health
   check : `GET /health`.
3. **Redis** : provisionner un service Redis avec persistance AOF, puis
   `VAULT_STORE=redis` + `REDIS_URL=redis://<host>:6379`.
4. **Secrets (variables d'env, jamais committés)** :
   - `PSEUDO_KEY_1` (32 octets hex) — clé de chiffrement courante,
   - `PSEUDO_INDEX_KEY` (32 octets hex) — clé d'index **stable**,
   - `GATEWAY_API_KEY` — partagé avec `files_service` (en-tête `X-Api-Key`).
   - Rotation : ajouter `PSEUDO_KEY_2`, passer `PSEUDO_CURRENT_KEY_ID=2`, redéployer.
5. **CACHEBUST** : bumper l'`ARG CACHEBUST` du `Dockerfile` pour forcer un rebuild.

> ⚠️ `/depseudonymize` restitue des données réelles : **ne jamais exposer la
> passerelle sans `GATEWAY_API_KEY`** (ou la garder sur réseau privé). `/health`
> et `/` restent ouverts pour les sondes.

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

**Clés & rotation** : chargées par un `KeyProvider` (aujourd'hui `EnvKeyProvider`,
demain Vault/KMS — même trait). Plusieurs versions `PSEUDO_KEY_<id>` cohabitent :
`PSEUDO_CURRENT_KEY_ID` chiffre, les anciennes versions déchiffrent toujours les
anciens blobs (cf. « Schéma de clés »). La clé d'index reste stable (déduplication
intacte au travers des rotations).

**Détection par spans** : la jetonisation collecte toutes les correspondances
(termes + regex) sur le texte d'origine, résout les chevauchements (« la plus longue
gagne ») puis insère les jetons par plage — fiable sur les sous-chaînes imbriquées
(« Marie » vs « Marie Dupont »), sans dépendre de l'ordre de remplacement.

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
