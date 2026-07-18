# Presidio Analyzer + modèle spaCy FRANÇAIS (phase B).
#
# L'image officielle n'embarque que le modèle anglais (en_core_web_lg) : sur
# un CV français, une partie des noms/villes passe au travers. On ajoute
# fr_core_news_lg (~570 Mo) et une conf déclarant les deux langues.
#
# `python -m spacy download` (plutôt qu'une URL de wheel épinglée) : il choisit
# automatiquement la version du modèle compatible avec le spaCy de l'image de
# base — pas de désynchronisation à la mise à jour de l'image.
FROM mcr.microsoft.com/presidio-analyzer:latest

RUN python -m spacy download fr_core_news_lg

# Conf en 3 fichiers séparés (schéma canonique, stable à travers les
# versions de l'image — la section registre INLINE dans l'analyzer conf est
# mal lue par certaines versions, cf. commentaires des yaml). Les 3 variables
# sont lues par l'app de l'image officielle au démarrage (app.py).
COPY analyzer-conf.yaml nlp-conf.yaml recognizers.yaml /app/conf-fr/
ENV ANALYZER_CONF_FILE=/app/conf-fr/analyzer-conf.yaml \
    NLP_CONF_FILE=/app/conf-fr/nlp-conf.yaml \
    RECOGNIZER_REGISTRY_CONF_FILE=/app/conf-fr/recognizers.yaml
