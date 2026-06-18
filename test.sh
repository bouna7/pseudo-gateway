#!/usr/bin/env bash
# Test de bout en bout de la passerelle (lancer `cargo run` dans un autre terminal d'abord).
set -e
BASE=${1:-http://localhost:8080}

echo "== 1. Pseudonymisation du document JohnTech =="
RESP=$(curl -s -X POST "$BASE/pseudonymize" \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "JohnTech a signe un contrat avec Marie Dupont (marie.dupont@gmail.com), montant 45000 EUR, IBAN FR76 3000 1007 9412.",
    "custom_terms": [
      {"type": "ORG", "value": "JohnTech"},
      {"type": "PERSON", "value": "Marie Dupont"}
    ]
  }')
echo "$RESP"
echo
echo "   -> C'est ce 'text' (avec jetons) que vous envoyez au LLM cloud."
echo

echo "== 2. Dé-pseudonymisation d'une reponse du LLM =="
curl -s -X POST "$BASE/depseudonymize" \
  -H 'Content-Type: application/json' \
  -d '{"text": "Le client du contrat est [PERSON_1], joignable a [EMAIL_1]."}'
echo
echo
echo "   -> Les vraies valeurs sont restituees a Spring AI."
