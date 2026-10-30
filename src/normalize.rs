//! Forme d'indexation d'une valeur sensible — ce qui décide si deux écritures
//! désignent la même chose.
//!
//! # Pourquoi ce module existe
//!
//! Le jeton d'une valeur vient d'un HMAC de cette valeur ([`crate::keys`]).
//! Tant que l'HMAC portait sur la chaîne BRUTE, « MAMADOU SOUMARE » écrit dans
//! un CV et « Soumare Mamadou » tapé dans une question donnaient deux jetons
//! différents. Le modèle recevait alors un contexte parlant de `[PERSON_1]` et
//! une question portant sur `[PERSON_8]`, et répondait — à juste titre — que
//! l'information ne s'y trouvait pas. Constaté le 30/10/2026 sur un CV indexé :
//! le bon document était retrouvé et cité en source, mais la réponse était
//! « aucune mention de cette personne ».
//!
//! On indexe donc une FORME CANONIQUE. La valeur réelle reste stockée chiffrée
//! telle qu'elle a été écrite la première fois : la restitution est intacte,
//! seule la déduplication devient tolérante à l'écriture.
//!
//! # Ce qu'on ne corrige pas
//!
//! Une faute de frappe (« mamdou » pour « mamadou ») reste une valeur
//! différente. Rapprocher des chaînes approximatives demanderait une distance
//! d'édition, donc un index qui n'est plus aveugle — on y perdrait la propriété
//! qui fait tout l'intérêt du coffre.

/// Replie une lettre accentuée latine sur sa base ASCII.
///
/// Écrit à la main plutôt qu'avec `unicode-normalization` : la plage latine
/// couvre le français, l'espagnol et l'allemand, et une dépendance de plus dans
/// l'image distroless se paie à chaque build.
fn fold(c: char) -> char {
    match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
        'ç' => 'c',
        'è' | 'é' | 'ê' | 'ë' => 'e',
        'ì' | 'í' | 'î' | 'ï' => 'i',
        'ñ' => 'n',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
        'ù' | 'ú' | 'û' | 'ü' => 'u',
        'ý' | 'ÿ' => 'y',
        other => other,
    }
}

/// Minuscules, sans accents, espaces normalisés.
fn base(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut space_pending = false;
    for c in value.chars().flat_map(char::to_lowercase).map(fold) {
        if c.is_whitespace() {
            // Un espace n'est émis que s'il sépare deux caractères utiles :
            // les espaces de tête, de queue et les répétitions disparaissent.
            space_pending = !out.is_empty();
        } else {
            if space_pending {
                out.push(' ');
                space_pending = false;
            }
            out.push(c);
        }
    }
    out
}

/// Forme sous laquelle une valeur est indexée, selon son type.
///
/// Deux valeurs partagent un jeton si et seulement si elles partagent cette
/// forme.
pub fn index_form(typ: &str, value: &str) -> String {
    match typ {
        // Un numéro ne change pas de nature selon sa ponctuation : « 06 11 81
        // 18 14 », « 06.11.81.18.14 » et « 0611811814 » sont le même téléphone.
        // Idem pour un IBAN ou un numéro de carte, qui s'écrivent groupés ou
        // d'un bloc selon la source.
        "PHONE" | "IBAN" | "CARD" => value
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect(),

        // Un nom se cite dans n'importe quel ordre : « Mamadou Soumare » sur un
        // CV, « SOUMARE Mamadou » dans un formulaire, « soumare mamadou » dans
        // une question. On trie les mots pour que l'ordre ne compte plus.
        //
        // Réservé aux personnes : trier les mots d'un nom d'organisation
        // rapprocherait des entités réellement distinctes.
        "PERSON" => {
            let canonical = base(value);
            let mut words: Vec<&str> = canonical.split(' ').filter(|w| !w.is_empty()).collect();
            words.sort_unstable();
            words.join(" ")
        }

        _ => base(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_nom_se_reconnait_quels_que_soient_la_casse_et_l_ordre() {
        let reference = index_form("PERSON", "MAMADOU SOUMARE");
        for ecriture in [
            "Mamadou Soumare",
            "soumare mamadou",
            "SOUMARE  Mamadou",
            "  Mamadou   SOUMARE  ",
        ] {
            assert_eq!(
                index_form("PERSON", ecriture),
                reference,
                "« {ecriture} » doit désigner la même personne"
            );
        }
    }

    #[test]
    fn les_accents_ne_separent_pas_deux_ecritures_du_meme_nom() {
        assert_eq!(index_form("PERSON", "Hélène Lefèvre"), index_form("PERSON", "HELENE LEFEVRE"));
    }

    #[test]
    fn deux_personnes_differentes_restent_differentes() {
        assert_ne!(index_form("PERSON", "Mamadou Soumare"), index_form("PERSON", "Bahissa Kebe"));
    }

    #[test]
    fn une_faute_de_frappe_reste_une_autre_valeur() {
        // Assumé : rapprocher des chaînes approximatives casserait l'index aveugle.
        assert_ne!(index_form("PERSON", "Mamadou Soumare"), index_form("PERSON", "Mamdou Soumare"));
    }

    #[test]
    fn un_numero_se_reconnait_quelle_que_soit_sa_ponctuation() {
        let reference = index_form("PHONE", "0611811814");
        for ecriture in ["06 11 81 18 14", "06.11.81.18.14", "06-11-81-18-14"] {
            assert_eq!(index_form("PHONE", ecriture), reference, "« {ecriture} »");
        }
    }

    #[test]
    fn un_iban_se_reconnait_groupe_ou_d_un_bloc() {
        assert_eq!(
            index_form("IBAN", "FR76 3000 6000 0112 3456 7890 189"),
            index_form("IBAN", "FR7630006000011234567890189")
        );
    }

    #[test]
    fn une_adresse_email_ne_depend_pas_de_la_casse() {
        assert_eq!(index_form("EMAIL", "Contact@RoostDrive.com"), index_form("EMAIL", "contact@roostdrive.com"));
    }

    #[test]
    fn un_nom_d_organisation_n_est_pas_trie() {
        // « Banque de France » et « France de Banque » ne sont pas la même chose.
        assert_ne!(index_form("ORG", "Banque de France"), index_form("ORG", "France de Banque"));
    }
}
