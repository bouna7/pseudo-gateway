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

### Sur Dokploy

1. **Application** dont la source est ce dépôt (build par le `Dockerfile`).
2. **Domaine** (le vôtre) → port conteneur **8080**, HTTPS. Health
   check : `GET /health`.
3. **Redis** : provisionner un service Redis avec persistance AOF, puis
   `VAULT_STORE=redis` + `REDIS_URL=redis://<host>:6379`.
4. **Secrets (variables d'env, jamais committés)** :
   - `PSEUDO_KEY_1` (32 octets hex) — clé de chiffrement courante,
   - `PSEUDO_INDEX_KEY` (32 octets hex) — clé d'index **stable**,
   - `GATEWAY_API_KEY` — partagé avec `files_service` (en-tête `X-Api-Key`).
   - Rotation : ajouter `PSEUDO_KEY_2`, passer `PSEUDO_CURRENT_KEY_ID=2`, redéployer.
5. **CACHEBUST** : bumper l'`ARG CACHEBUST` du `Dockerfile` pour forcer un rebuild.

### Checklist de mise en production

`/depseudonymize` restitue des **données réelles** : une instance ouverte est une
fuite, pas un mode dégradé. Le service refuse d'ailleurs de démarrer sans aucune
clé (`ALLOW_INSECURE=true` pour passer outre en local).

| # | À vérifier | Pourquoi |
|---|---|---|
| 1 | `PSEUDO_KEY_1` **et** `PSEUDO_INDEX_KEY` définies | Sans elles, une clé de DEV éphémère est tirée : tous les jetons deviennent illisibles au redémarrage |
| 2 | `GATEWAY_API_KEY` (vos services) **et/ou** `ADMIN_API_KEY` (clients externes) | Sans clé, n'importe qui restitue les valeurs réelles |
| 3 | `PUBLIC_SIGNUP=false` | Sinon n'importe qui crée des comptes. Créez-les via `/admin/accounts` |
| 4 | `VAULT_STORE=redis` avec persistance AOF | En mémoire, le coffre est perdu au redémarrage |
| 5 | HTTPS, et `TRUST_PROXY=true` derrière Traefik / nginx | Les clés circuleraient en clair ; et les limites par IP se tromperaient de client |
| 6 | `/admin/*` réservé à votre réseau, ou `ADMIN_API_KEY` longue et tournée régulièrement | Ces routes créent des comptes et des clés |
| 7 | `ENABLE_DOCS` selon que vous publiez ou non votre documentation | Par défaut la doc est fermée et `/` ne répond rien |
| 8 | Sauvegarde de Redis **et** des clés de chiffrement | Les blobs sans leur clé sont irrécupérables |

La clé interne `GATEWAY_API_KEY` est une **clé maîtresse** : elle choisit
librement son `tenant_id` et lit donc les jetons de n'importe quel compte. Elle
est faite pour vos propres services — ne la donnez jamais à un client externe,
donnez-lui une clé de compte `pgw_…`.

`/health` reste ouvert pour les sondes.

## Installer partout (Linux, Windows, macOS — x86_64 et ARM64)

Chaque tag `vX.Y.Z` poussé sur GitHub déclenche `.github/workflows/release.yml`,
qui publie les binaires dans une Release et les images multi-arch sur GHCR :

```bash
git tag v0.2.0 && git push origin v0.2.0
```

**Option 1 — Docker, tout-en-un (Redis + Presidio + passerelle)** : aucune compilation.

```bash
mkdir pseudo-gateway && cd pseudo-gateway
curl -LO https://github.com/bouna7/pseudo-gateway/releases/latest/download/docker-compose.yml
curl -L -o .env https://github.com/bouna7/pseudo-gateway/releases/latest/download/env.example
docker run --rm ghcr.io/bouna7/pseudo-gateway gen-keys   # coller le résultat dans .env
docker compose up -d                                      # http://localhost:8080
```

**Option 2 — binaire seul** (sans Docker ; coffre mémoire ou Redis existant).
Chaque système a **sa** commande : celle de Linux ne fonctionne pas dans
PowerShell (`sh` n'y existe pas), et inversement.

**Linux / macOS**, dans un terminal :

```bash
curl -fsSL https://github.com/bouna7/pseudo-gateway/releases/latest/download/install.sh | sh
pseudo-gateway gen-keys > .env
pseudo-gateway                      # http://localhost:8080
```

**Windows**, dans PowerShell :

```powershell
irm https://github.com/bouna7/pseudo-gateway/releases/latest/download/install.ps1 | iex
& "$env:LOCALAPPDATA\pseudo-gateway\pseudo-gateway.exe" gen-keys | Out-File -Encoding ascii .env
& "$env:LOCALAPPDATA\pseudo-gateway\pseudo-gateway.exe"
```

> `Out-File -Encoding ascii` (et non `>`) : la redirection de PowerShell écrit en
> UTF-16, que le lecteur de `.env` ne sait pas lire.

Les scripts vérifient l'empreinte SHA-256 de l'archive. Le binaire lit sa
configuration dans l'environnement ou dans un fichier `.env` du dossier courant
(voir `.env.example`). `pseudo-gateway --help` liste les commandes.

Par défaut, la documentation n'est pas publiée et la racine `/` ne répond rien :
ajoutez `ENABLE_DOCS=true` au `.env` pour ouvrir `/docs` (`/` y redirige alors).
Sans Redis ni Presidio, le service démarre quand même : coffre en mémoire et
détection par regex seule (e-mail, téléphone, IBAN, carte), sans les noms.

> Le dépôt et les paquets GHCR doivent être **publics** pour que ces URL
> fonctionnent sans authentification (GitHub → Packages → *Change visibility*).

## API publique (comptes, clés, quotas)

Définir `ADMIN_API_KEY` active la gestion de comptes. Chaque utilisateur reçoit
une clé `pgw_…` (stockée hachée, affichée une seule fois) et dispose de son
**propre espace de jetons** : le tenant est imposé par le serveur (`acc_<id>`,
et `tenant_id` ne cloisonne qu'à l'intérieur du compte). Un compte ne peut donc
jamais restituer les jetons d'un autre, même en forgeant `tenant_id`.

`GATEWAY_API_KEY` reste la clé **interne** (files_service) : elle choisit
librement son `tenant_id`, comme avant. Ne la donnez jamais à un tiers.

| Endpoint | Auth | Rôle |
|---|---|---|
| `POST /v1/pseudonymize`, `POST /v1/depseudonymize` | clé compte ou interne | Décomptés (limite/minute + quota mensuel) |
| `GET /v1/me` | clé compte | Compte + consommation du mois (non décompté) |
| `POST /v1/signup` | aucune | Inscription libre si `PUBLIC_SIGNUP=true` (limitée par IP) |
| `POST/GET /admin/accounts`, `GET/PATCH /admin/accounts/{id}` | `X-Admin-Key` | Créer, lister, modifier, désactiver |
| `POST /admin/accounts/{id}/keys`, `DELETE …/keys/{key_id}` | `X-Admin-Key` | Rotation / révocation de clé |

La clé se passe en `X-Api-Key: <clé>` **ou** `Authorization: Bearer <clé>`.
Dépassements : `429` avec `Retry-After` (`rate_limited`) ou `quota_exceeded`.
Les anciens chemins `/pseudonymize` et `/depseudonymize` restent servis.

```bash
# Créer un compte (admin)
curl -X POST https://votre-domaine.exemple/admin/accounts \
  -H "X-Admin-Key: $ADMIN_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name": "Acme", "email": "dev@acme.fr", "rate_per_min": 120, "monthly_quota": 50000}'
# -> { "account": { "id": "acc_…", … }, "api_key": "pgw_…" }

# Appel par le client, depuis n'importe quelle machine
curl -X POST https://votre-domaine.exemple/v1/pseudonymize \
  -H "Authorization: Bearer pgw_…" -H 'Content-Type: application/json' \
  -d '{"text": "Écrire à marie.dupont@gmail.com"}'
```

Réglages associés : `DEFAULT_RATE_PER_MIN`, `DEFAULT_MONTHLY_QUOTA`,
`SIGNUP_PER_IP_PER_HOUR`, `TRUST_PROXY` (IP réelle derrière Traefik),
`CORS_ALLOWED_ORIGINS` (appels depuis un navigateur), `ENABLE_DOCS` (doc
interactive sur `/docs`, spec sur `/openapi.json`), `PUBLIC_BASE_URL`,
`MAX_BODY_BYTES`, `REQUEST_TIMEOUT_SECS`, `PORT`, `BIND_ADDR`.

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
├── Dockerfile.release   # image multi-arch à partir des binaires de release
├── install.sh / install.ps1
├── deploy/docker-compose.yml   # pile tout-en-un à partir des images GHCR
├── .github/workflows/   # ci.yml (tests 3 OS) + release.yml (binaires + images)
└── src/
    ├── main.rs          # démarrage : configuration, stores, sous-commandes
    ├── app.rs           # état partagé + routeur (CORS, limites, doc)
    ├── api.rs           # endpoints /v1 + spec OpenAPI
    ├── admin.rs         # /admin : comptes et clés
    ├── auth.rs          # clés interne / compte / admin
    ├── accounts.rs      # comptes, clés hachées, limites et quotas (mémoire / Redis)
    ├── crypto.rs        # chiffrement AES-256-GCM brut
    ├── keys.rs          # trousseau : chiffrement versionné + blind index HMAC
    ├── store.rs         # trait VaultStore + InMemoryVaultStore
    ├── error.rs         # AppError / VaultError -> réponses HTTP propres
    ├── ner.rs           # client NER Presidio (best effort)
    └── pseudonymize.rs  # détection + jetonnage (async, adossé au VaultStore)
```
