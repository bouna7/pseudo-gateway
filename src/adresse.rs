//! Détection des adresses postales françaises.
//!
//! # Le défaut que ce module corrige
//!
//! La détection automatique découpait l'adresse et laissait le numéro de voie
//! en clair. Mesuré en production le 2026-11-11 :
//!
//! ```text
//! "Jean Martin habite 12 rue des Lilas a Lyon"
//!   ->  "[PERSON_1] habite 12 [LOC_1] a [LOC_2]"
//! ```
//!
//! Presidio étiquette la voie (« rue des Lilas ») mais jamais le numéro qui la
//! précède : un nombre seul n'est pas une entité. Or c'est le numéro qui
//! distingue un foyer parmi les quelques centaines d'une rue — le masquer est
//! précisément ce qui rend l'adresse non identifiante.
//!
//! # Ce que ce module couvre
//!
//! Un numéro suivi d'un type de voie français, étendu sur le nom de la voie
//! puis, s'il suit, sur le code postal et la commune. **Sans la détection
//! automatique** : une regex et un balayage de mots, donc aussi quand Presidio
//! est mort — ce qui est arrivé deux fois cette année.
//!
//! # Ce qu'il ne couvre pas, et pourquoi
//!
//! Un code postal **seul** (« 75011 Paris » en tête de CV) n'est pas reconnu :
//! `\d{5}` suivi d'un mot capitalisé attrape aussi « 35000 Euros », et masquer
//! un montant coûte à la compréhension du texte plus que ce cas ne rapporte.
//! La commune, elle, reste couverte par le NER.
//!
//! Deux types de voie ambigus sont écartés volontairement : « cours » et
//! « voie », qui feraient de « 3 cours de maths » et « 2 voies de circulation »
//! des adresses. Un faux positif n'est pas une fuite, mais il ampute le texte
//! envoyé au modèle d'une information qui n'avait rien de personnel.

use crate::normalize;
use once_cell::sync::Lazy;
use regex::Regex;

/// L'ancre : numéro de voie + type de voie. Tout le reste s'étend depuis sa fin.
///
/// Les abréviations exigent leur point (`av.`, `bd.`) : « av » nu est trop
/// ambigu, et un `\b` placé après un point ne pourrait de toute façon pas
/// matcher devant une espace.
static ANCRE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b\d{1,4}\s*(?:bis|ter|quater)?\s*,?\s*(?:(?:grande rue|rue|avenue|boulevard|impasse|all[ée]e|chemin|route|place|quai|square|passage|faubourg|esplanade|r[ée]sidence|lotissement|hameau|sentier|promenade|parvis|rond-point|lieu-dit)\b|(?:av|bd|bld|blvd|pl|rte|imp|all|ch)\.)",
    )
    .expect("regex d'ancre d'adresse valide")
});

/// Séparateur entre deux mots d'une adresse : espaces, au plus une virgule et
/// au plus un retour à la ligne (un bloc d'adresse se replie avant la commune).
static SEPARATEUR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[ \t]*,?[ \t]*(?:\r?\n[ \t]*)?").expect("regex de séparateur valide")
});

/// Code postal précédé de son séparateur. La longueur du match sert de preuve
/// qu'il y avait bien un séparateur : 5 tout rond voudrait dire « collé au mot
/// précédent », donc pas un code postal.
static CODE_POSTAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[ \t]*,?[ \t]*(?:\r?\n[ \t]*)?\d{5}\b").expect("regex de code postal valide")
});

/// Mots de liaison d'un nom de voie. Ils ne comptent pas comme un mot plein et
/// ne peuvent pas terminer l'adresse : « 12 rue des » n'est pas une adresse.
const PARTICULES: &[&str] = &["de", "du", "des", "d'", "la", "le", "les", "l'", "au", "aux"];

/// Mots qui ne font jamais partie d'un nom de lieu : l'extension s'arrête
/// dessus. Liste volontairement courte — ce sont les plafonds (`MAX_MOTS_VOIE`,
/// `MAX_OCTETS`) qui bornent ce qu'un oubli peut coûter, pas l'exhaustivité.
const STOP: &[&str] = &[
    "et", "ou", "en", "est", "sont", "etait", "ete", "sera", "il", "elle", "on", "je", "tu",
    "nous", "vous", "ils", "elles", "ce", "cet", "cette", "ces", "se", "si", "ne", "pas", "plus",
    "que", "qui", "quoi", "dont", "mais", "donc", "car", "ni", "puis", "chez", "dans", "pour",
    "avec", "sans", "sous", "sur", "par", "vers", "depuis", "apres", "avant", "entre", "jusqu",
    "tel", "tels", "telephone", "portable", "mail", "email", "numero", "un", "une", "mon", "ma",
    "mes", "ton", "ta", "tes", "son", "sa", "ses", "notre", "nos", "votre", "vos", "leur",
    "leurs", "tout", "tous", "toute", "toutes", "meme", "aussi", "tres", "bien", "comme",
    "quand", "alors", "ici",
    // Mots de situation : « 2 chemin de la Croix, pres de Nantes » s'arrête
    // avant « pres », sinon l'adresse avale la ville et le commentaire.
    "pres", "proche", "loin", "autour", "environ", "via", "face",
];

/// Nom de voie : « boulevard de la Croix Rousse Nord » en fait trois pleins.
const MAX_MOTS_VOIE: usize = 4;
/// Commune après le code postal. Les communes composées s'écrivent presque
/// toujours avec des traits d'union, qui ne coupent pas un mot ici.
const MAX_MOTS_COMMUNE: usize = 3;
/// Au-delà, on ne lit plus une adresse mais la phrase qui l'entoure.
const MAX_OCTETS: usize = 60;

/// Plages d'octets des adresses trouvées dans `text`, dans l'ordre du texte.
pub fn trouver(text: &str) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for m in ANCRE.find_iter(text) {
        // Une plage étendue peut recouvrir l'ancre suivante : la première gagne.
        if let Some((_, fin)) = out.last() {
            if m.start() < *fin {
                continue;
            }
        }
        out.push((m.start(), etendre(text, m.end())));
    }
    out
}

/// Fin de l'adresse dont l'ancre s'arrête à `apres_ancre`.
fn etendre(text: &str, apres_ancre: usize) -> usize {
    let fin_voie = mots_de_lieu(text, apres_ancre, MAX_MOTS_VOIE);
    match CODE_POSTAL.find(&text[fin_voie..]) {
        // 5 = le code postal sans séparateur, donc collé : ce n'en est pas un.
        Some(m) if m.end() > 5 => mots_de_lieu(text, fin_voie + m.end(), MAX_MOTS_COMMUNE),
        _ => fin_voie,
    }
}

/// Étend `depuis` sur au plus `max` mots pleins d'un nom de lieu, et renvoie la
/// fin du dernier mot plein retenu (donc `depuis` si aucun ne convient).
fn mots_de_lieu(text: &str, depuis: usize, max: usize) -> usize {
    let mut fin = depuis;
    let mut curseur = depuis;
    let mut mots = 0;
    while mots < max && curseur - depuis <= MAX_OCTETS {
        let Some(saut) = SEPARATEUR
            .find(&text[curseur..])
            .map(|m| m.end())
            .filter(|n| *n > 0)
        else {
            break;
        };
        let debut_mot = curseur + saut;
        let mot = mot_a(text, debut_mot);
        if mot.is_empty() || colle_a_un_identifiant(text, debut_mot + mot.len()) {
            break;
        }
        let canonique = normalize::base(mot);
        curseur = debut_mot + mot.len();
        if PARTICULES.contains(&canonique.as_str()) {
            continue; // avancé, mais une particule ne termine pas une adresse
        }
        // Un mot d'une seule lettre est une préposition (« a Lyon »), pas un
        // nom de voie : c'est lui qui arrête l'extension dans le cas mesuré.
        if mot.chars().count() < 2 || STOP.contains(&canonique.as_str()) {
            break;
        }
        fin = curseur;
        mots += 1;
    }
    fin
}

/// Le mot qui s'arrête à `apres_mot` est-il le début d'un identifiant plutôt
/// qu'un nom de voie ?
///
/// Un « @ » ou un point collé à un caractère de mot trahit un courriel ou un
/// domaine : dans « 12 rue des Lilas jean.martin@exemple.fr », « jean » se lit
/// comme un mot ordinaire. L'avaler rangerait une adresse électronique sous le
/// type `ADDRESS`, et le même courriel rencontré ailleurs recevrait un autre
/// jeton. Un point suivi d'une espace ou d'une fin de texte, lui, ne termine
/// qu'une phrase : « 5 rue du Faubourg Saint-Antoine. » reste une adresse.
fn colle_a_un_identifiant(text: &str, apres_mot: usize) -> bool {
    let mut suite = text[apres_mot..].chars();
    match suite.next() {
        Some('@') => true,
        Some('.') => matches!(suite.next(), Some(c) if c.is_alphanumeric()),
        _ => false,
    }
}

/// Mot commençant à l'octet `i` : lettres, trait d'union et apostrophe, pour que
/// « Saint-Antoine » et « l'Église » restent d'un seul tenant. Tout le reste —
/// chiffre, arobase, ponctuation — termine le mot, ce qui empêche une adresse
/// d'avaler le téléphone ou le courriel qui la suit.
fn mot_a(text: &str, i: usize) -> &str {
    let reste = &text[i..];
    let n = reste
        .char_indices()
        .take_while(|(_, c)| c.is_alphabetic() || *c == '\'' || *c == '\u{2019}' || *c == '-')
        .map(|(o, c)| o + c.len_utf8())
        .last()
        .unwrap_or(0);
    &reste[..n]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trouvees(text: &str) -> Vec<&str> {
        trouver(text).into_iter().map(|(s, e)| &text[s..e]).collect()
    }

    #[test]
    fn le_numero_de_voie_entre_dans_l_adresse() {
        // Le cas mesuré en production : « 12 » restait en clair.
        assert_eq!(
            trouvees("Jean Martin habite 12 rue des Lilas a Lyon"),
            vec!["12 rue des Lilas"]
        );
    }

    #[test]
    fn la_preposition_arrete_l_extension_et_pas_le_nom_de_la_voie() {
        assert_eq!(
            trouvees("au 3 avenue du Général de Gaulle à Paris"),
            vec!["3 avenue du Général de Gaulle"]
        );
        assert_eq!(trouvees("1 rue de l'Église et puis rien"), vec!["1 rue de l'Église"]);
        assert_eq!(
            trouvees("5 rue du Faubourg Saint-Antoine."),
            vec!["5 rue du Faubourg Saint-Antoine"]
        );
    }

    #[test]
    fn le_code_postal_et_la_commune_rejoignent_l_adresse() {
        assert_eq!(
            trouvees("12 rue des Lilas, 75011 Paris"),
            vec!["12 rue des Lilas, 75011 Paris"]
        );
        // Bloc d'adresse replié, tel qu'un CV l'écrit.
        assert_eq!(
            trouvees("12 rue des Lilas\n75011 Paris Cedex"),
            vec!["12 rue des Lilas\n75011 Paris Cedex"]
        );
    }

    #[test]
    fn un_nombre_colle_n_est_pas_un_code_postal() {
        // « Lilas75011 » n'existe pas : sans séparateur, pas de code postal.
        assert_eq!(trouvees("12 rue des Lilas75011"), vec!["12 rue des Lilas"]);
    }

    #[test]
    fn les_formes_d_ecriture_du_numero_sont_admises() {
        assert_eq!(trouvees("12, rue des Lilas"), vec!["12, rue des Lilas"]);
        assert_eq!(trouvees("12 bis rue des Lilas"), vec!["12 bis rue des Lilas"]);
        assert_eq!(trouvees("12 BIS RUE DES LILAS"), vec!["12 BIS RUE DES LILAS"]);
        assert_eq!(trouvees("7 av. des Champs"), vec!["7 av. des Champs"]);
    }

    #[test]
    fn une_adresse_n_avale_pas_la_donnee_qui_la_suit() {
        // La frontière compte : un courriel absorbé serait masqué sous le type
        // ADDRESS, et le même courriel ailleurs recevrait un autre jeton.
        assert_eq!(
            trouvees("12 rue des Lilas jean.martin@exemple.fr"),
            vec!["12 rue des Lilas"]
        );
        assert_eq!(
            trouvees("12 rue des Lilas 06 11 81 18 14"),
            vec!["12 rue des Lilas"]
        );
    }

    #[test]
    fn un_mot_de_situation_arrete_l_adresse() {
        // Sans ce garde-fou, l'adresse avalait « pres de Nantes » en entier.
        assert_eq!(
            trouvees("il habite au 2 chemin de la Croix, pres de Nantes"),
            vec!["2 chemin de la Croix"]
        );
    }

    /// Les écritures réelles, relevées sur des CV et des en-têtes de courrier.
    #[test]
    fn les_ecritures_courantes_sont_couvertes() {
        assert_eq!(
            trouvees("MAMADOU SOUMARE\n12 BIS RUE DES LILAS\n75011 PARIS\n06 11 81 18 14"),
            vec!["12 BIS RUE DES LILAS\n75011 PARIS"]
        );
        assert_eq!(
            trouvees("Siege : 7 rue d'Alsace-Lorraine, 31000 Toulouse (France)"),
            vec!["7 rue d'Alsace-Lorraine, 31000 Toulouse"]
        );
        assert_eq!(
            trouvees("Livraison 15 route de Vannes 44800 Saint-Herblain Cedex 2"),
            vec!["15 route de Vannes 44800 Saint-Herblain Cedex"]
        );
        assert_eq!(
            trouvees("La societe est au 1 bd. Haussmann, Paris"),
            vec!["1 bd. Haussmann, Paris"]
        );
        // Un montant n'est pas une adresse, même suivi d'un mot qui y ressemble.
        assert!(trouvees("j'ai paye 3500 euros pour 2 places de concert").is_empty());
    }

    #[test]
    fn l_extension_ne_depasse_pas_la_phrase() {
        // Quatre mots pleins au plus : la suite de la phrase reste dehors.
        assert_eq!(
            trouvees("4 place Jean Moulin Nord Ouest Sud Est"),
            vec!["4 place Jean Moulin Nord Ouest"]
        );
    }

    #[test]
    fn une_adresse_sans_nom_de_voie_reste_une_adresse() {
        // « 12 rue » seul : l'ancre suffit, rien à étendre.
        assert_eq!(trouvees("12 rue, puis à gauche"), vec!["12 rue"]);
    }

    #[test]
    fn les_types_de_voie_ambigus_sont_ecartes() {
        // Choix documenté en tête de module : un faux positif ampute le texte
        // envoyé au modèle d'une information qui n'a rien de personnel.
        assert!(trouvees("il prend 3 cours de maths").is_empty());
        assert!(trouvees("2 voies de circulation").is_empty());
        // Un pluriel n'est pas un type de voie.
        assert!(trouvees("2 places de parking").is_empty());
    }

    #[test]
    fn plusieurs_adresses_dans_un_meme_texte() {
        assert_eq!(
            trouvees("de 12 rue des Lilas à 7 avenue Foch"),
            vec!["12 rue des Lilas", "7 avenue Foch"]
        );
    }

    #[test]
    fn un_texte_sans_adresse_ne_produit_rien() {
        assert!(trouvees("Jean Martin habite à Lyon depuis 2012").is_empty());
        assert!(trouvees("").is_empty());
    }
}
