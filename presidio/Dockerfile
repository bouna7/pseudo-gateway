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

# Conf moteur (langues supportées, mapping NER → entités Presidio).
# ANALYZER_CONF_FILE est lu par l'app de l'image officielle au démarrage.
COPY analyzer-conf.yaml /app/analyzer-conf.yaml
ENV ANALYZER_CONF_FILE=/app/analyzer-conf.yaml
