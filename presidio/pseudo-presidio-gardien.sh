#!/bin/sh
# Gardien : vérifie que Presidio DÉTECTE, et le repose sinon.
#
# Pourquoi reposer plutôt que redémarrer : un `docker restart` ne guérit pas un
# Presidio muet, ni un `docker compose up --force-recreate` (vérifié le
# 2026-11-11). Un conteneur recréé hors compose, lui, sert correctement — six
# fois sur six. Le gardien appelle donc `presidio-autonome.sh`, qui
# reconstruit, exige une détection sur un texte témoin, et ne bascule
# qu'ensuite.
#
# Le cas qu'il couvre : le conteneur disparaît. Le 2026-11-11, `presidio-manuel`
# a été supprimé par une opération de la plateforme que nous n'avons pas
# identifiée, et plus rien ne masquait les noms — sans aucun signal, puisque
# `/health` répond « ok » dans cet état.
#
# Installation : voir la section « Presidio (NER) vit hors compose » du README.
# Les deux variables viennent de /etc/default/pseudo-presidio-gardien :
#   CHEMIN=<dépôt cloné>      (utilisé par l'unité systemd)
#   RESEAU=<pile>_default     (lu par presidio-autonome.sh)
set -eu

NOM="${NOM:-pseudo-presidio}"
TEMOIN='{"text":"Jean Martin habite a Lyon","language":"fr"}'
ici=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if docker exec "$NOM" curl -sf -m 10 -X POST localhost:3000/analyze \
    -H 'Content-Type: application/json' -d "$TEMOIN" 2>/dev/null |
    grep -q PERSON; then
    echo "Presidio détecte — rien à faire."
    exit 0
fi

echo "Presidio ne détecte rien : conteneur « $NOM » absent, arrêté ou muet."
echo "Les noms, villes et organisations partaient en clair. On le repose."
exec "$ici/presidio-autonome.sh"
