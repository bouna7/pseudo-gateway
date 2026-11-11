#!/bin/sh
# Pose (ou remplace) le conteneur Presidio de production, HORS compose.
#
# Pourquoi hors compose : un conteneur presidio créé par `docker compose`
# n'amorce jamais son worker gunicorn sur le VPS de production — le port
# écoute, aucune requête n'est servie, et la passerelle retombe en silence sur
# ses quatre regex : les noms, les villes et les organisations partent EN CLAIR
# au modèle. Le même conteneur lancé par `docker run` sert correctement
# (vérifié six fois le 2026-11-11, en faisant varier l'image, le niveau de
# journal, le réseau, l'attachement des flux et la politique de redémarrage).
# La cause reste inconnue, et ni `docker restart` ni `compose up
# --force-recreate` ne guérissent le conteneur fautif.
#
# Ce que ce script garantit : on ne bascule la production QUE sur un Presidio
# dont on a vérifié qu'il **détecte**. Un port qui écoute ne prouve rien —
# c'est exactement l'erreur qui a coûté 2 h 45 de fuite le 2026-11-11.
#
# Usage :
#   RESEAU=pseudopro-gateway-nhsae7_default ./presidio/presidio-autonome.sh
#
# Le réseau est celui de la pile compose (`docker network ls`), pour que la
# passerelle joigne ce conteneur sous le nom d'hôte `presidio`.
set -eu

IMAGE="${IMAGE:-pseudo-presidio:local}"
NOM="${NOM:-pseudo-presidio}"
ALIAS="${ALIAS:-presidio}"
RESEAU="${RESEAU:-}"
CANDIDAT="$NOM-candidat"
TEMOIN='{"text":"Jean Martin habite a Lyon","language":"fr"}'
ESSAIS=24 # 24 × 5 s = 2 min, large pour les 20 à 60 s de chargement du modèle

if [ -z "$RESEAU" ]; then
    echo "RESEAU= manquant. Exemple :" >&2
    echo "  RESEAU=\$(docker network ls --format '{{.Name}}' | grep _default | head -1) $0" >&2
    exit 2
fi
if ! docker network inspect "$RESEAU" >/dev/null 2>&1; then
    echo "Le réseau « $RESEAU » n'existe pas. Choix possibles :" >&2
    docker network ls --format '  {{.Name}}' >&2
    exit 2
fi

ici=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

echo "1/4  construction de $IMAGE"
docker build -t "$IMAGE" "$ici"

echo "2/4  démarrage d'un candidat SANS l'alias « $ALIAS » (la production sert toujours)"
docker rm -f "$CANDIDAT" >/dev/null 2>&1 || true
docker run -d --name "$CANDIDAT" --network "$RESEAU" \
    -e GUNICORN_CMD_ARGS="--timeout 300" "$IMAGE" >/dev/null

echo "3/4  vérification : on exige une détection, pas un port ouvert"
essai=0
detecte=0
while [ "$essai" -lt "$ESSAIS" ]; do
    if docker exec "$CANDIDAT" curl -sf -m 10 -X POST localhost:3000/analyze \
        -H 'Content-Type: application/json' -d "$TEMOIN" 2>/dev/null |
        grep -q PERSON; then
        detecte=1
        break
    fi
    essai=$((essai + 1))
    sleep 5
done

if [ "$detecte" -eq 0 ]; then
    echo >&2
    echo "ÉCHEC : le candidat ne détecte rien après 2 min. Journal :" >&2
    docker logs "$CANDIDAT" --tail 20 >&2
    echo >&2
    echo "La production n'a PAS été touchée. Le candidat « $CANDIDAT » est" >&2
    echo "laissé en place pour diagnostic (docker rm -f $CANDIDAT pour l'ôter)." >&2
    echo "Si « Booting worker » manque, c'est la panne décrite en tête de ce" >&2
    echo "script : réessayer, ou repartir d'une image connue bonne." >&2
    exit 1
fi
echo "     détection confirmée (une personne reconnue dans le texte témoin)"

echo "4/4  bascule"
docker rm -f "$NOM" >/dev/null 2>&1 || true
docker rename "$CANDIDAT" "$NOM"
# L'alias ne peut être posé qu'en rattachant le réseau : on l'ajoute seulement
# maintenant, pour qu'aucune requête n'ait pu atteindre un candidat non vérifié.
docker network disconnect "$RESEAU" "$NOM"
docker network connect --alias "$ALIAS" "$RESEAU" "$NOM"
docker update --restart unless-stopped "$NOM" >/dev/null

echo
echo "OK — « $NOM » répond au nom « $ALIAS » sur le réseau « $RESEAU »,"
echo "     et redémarrera avec la machine."
echo
echo "À vérifier depuis l'extérieur : GET /health/ner doit répondre 200."
