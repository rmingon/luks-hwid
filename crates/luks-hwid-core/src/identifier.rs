use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use blake2::{Blake2b512, Digest};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Classe d'identifiant matériel. L'ordre des variantes fixe l'ordre de tri
/// déterministe de `collect_all`, et donc la priorité en cas de troncature.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IdClass {
    RamSerial,
    Cpu,
    BoardSerial,
    ProductUuid,
    UsbDevice,
}

impl IdClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            IdClass::RamSerial => "ram_serial",
            IdClass::Cpu => "cpu",
            IdClass::BoardSerial => "board_serial",
            IdClass::ProductUuid => "product_uuid",
            IdClass::UsbDevice => "usb_device",
        }
    }
}

impl fmt::Display for IdClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Valeurs constructeur sans aucune valeur d'identification, rejetées
/// après canonicalisation (comparaison en minuscules).
const BLACKLIST: &[&str] = &[
    "to be filled by o.e.m.",
    "to be filled by oem",
    "default string",
    "0123456789",
    "123456789",
    "1234567890",
    "system serial number",
    "serial number",
    "base board serial number",
    "board serial number",
    "chassis serial number",
    "none",
    "unknown",
    "not specified",
    "not available",
    "no serial",
    "empty",
    "n/a",
    "na",
    "oem",
    "invalid",
    "invalid entry",
    // product_uuid de repli très répandu sur les cartes sans UUID programmé
    "03000200-0400-0500-0006-000700080009",
];

/// Canonicalise une valeur brute : espaces effondrés, trim, minuscules.
/// Retourne `None` si la valeur est une valeur poubelle sans entropie.
pub(crate) fn canonicalize(raw: &str) -> Option<String> {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let v = collapsed.to_lowercase();
    if v.chars().count() < 2 {
        return None;
    }
    let first = v.chars().next().expect("non vide");
    if v.chars().all(|c| c == first) {
        return None;
    }
    if BLACKLIST.contains(&v.as_str()) {
        return None;
    }
    // Valeurs "structurées mais vides" : uniquement des 0 ou des f
    // une fois les séparateurs retirés (ex: 00-00-00, ffff:ffff, 0.0.0).
    let stripped: String = v
        .chars()
        .filter(|c| !matches!(c, '-' | ':' | '.' | '_' | ' '))
        .collect();
    if stripped.is_empty()
        || stripped.chars().all(|c| c == '0')
        || stripped.chars().all(|c| c == 'f')
    {
        return None;
    }
    Some(v)
}

/// Un identifiant matériel canonicalisé.
///
/// La valeur n'est jamais exposée : pas de `Display`, un `Debug` qui ne
/// montre que l'empreinte tronquée, zéroïsation au drop. Seule `hint()`
/// (4 octets de BLAKE2b, hexadécimal) sort de la crate.
#[derive(Clone)]
pub struct Identifier {
    class: IdClass,
    value: String,
}

impl Identifier {
    /// Canonicalise et filtre. `None` = valeur poubelle, à ignorer en silence.
    pub fn new(class: IdClass, raw: &str) -> Option<Self> {
        canonicalize(raw).map(|value| Identifier { class, value })
    }

    pub fn class(&self) -> IdClass {
        self.class
    }

    /// Empreinte tronquée pour le diagnostic et les métadonnées :
    /// 8 caractères hexadécimaux de BLAKE2b-512 en contexte dédié.
    pub fn hint(&self) -> String {
        let mut h = Blake2b512::new();
        h.update(b"luks-hwid-hint-v1\0");
        h.update(self.class.as_str().as_bytes());
        h.update(b"\0");
        h.update(self.value.as_bytes());
        let digest = h.finalize();
        digest[..4].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Matière première de la KDF : classe + valeur, séparées par un NUL
    /// pour la séparation de domaines entre classes.
    pub(crate) fn kdf_input(&self) -> Zeroizing<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.class.as_str().len() + 1 + self.value.len());
        buf.extend_from_slice(self.class.as_str().as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.value.as_bytes());
        Zeroizing::new(buf)
    }
}

impl Drop for Identifier {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identifier")
            .field("class", &self.class)
            .field("hint", &self.hint())
            .finish()
    }
}

impl PartialEq for Identifier {
    fn eq(&self, other: &Self) -> bool {
        self.class == other.class && self.value == other.value
    }
}
impl Eq for Identifier {}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.class, &self.value).cmp(&(other.class, &other.value))
    }
}

impl Hash for Identifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.class.hash(state);
        self.value.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalise_trim_minuscules_espaces() {
        assert_eq!(
            canonicalize("  SN  12345\tABC  ").as_deref(),
            Some("sn 12345 abc")
        );
    }

    #[test]
    fn rejette_les_valeurs_poubelle() {
        for junk in [
            "To Be Filled By O.E.M.",
            "Default string",
            "0123456789",
            "  DEFAULT   STRING ",
            "System Serial Number",
            "None",
            "N/A",
            "",
            "   ",
            "x",
            "0000000000",
            "00-00-00-00",
            "FF:FF:FF:FF",
            "AAAAAAAA",
            "........",
            "03000200-0400-0500-0006-000700080009",
        ] {
            assert!(
                Identifier::new(IdClass::BoardSerial, junk).is_none(),
                "aurait dû être rejeté : {junk:?}"
            );
        }
    }

    #[test]
    fn accepte_les_valeurs_reelles() {
        for good in [
            "CZC1234ABC",
            "4C4C4544-0042-3010-8058-B4C04F565432",
            "8dc12dba",
            "0000:00:14.0",
        ] {
            assert!(
                Identifier::new(IdClass::BoardSerial, good).is_some(),
                "aurait dû être accepté : {good:?}"
            );
        }
    }

    #[test]
    fn hint_stable_et_dependant_de_la_classe() {
        let a = Identifier::new(IdClass::RamSerial, "ABC123").unwrap();
        let b = Identifier::new(IdClass::RamSerial, "abc123").unwrap();
        let c = Identifier::new(IdClass::BoardSerial, "ABC123").unwrap();
        assert_eq!(a.hint(), b.hint(), "canonicalisation avant hachage");
        assert_ne!(a.hint(), c.hint(), "séparation de domaines par classe");
        assert_eq!(a.hint().len(), 8);
    }

    #[test]
    fn debug_ne_montre_pas_la_valeur() {
        let id = Identifier::new(IdClass::RamSerial, "TOPSECRET42").unwrap();
        let dbg = format!("{id:?}");
        assert!(!dbg.to_lowercase().contains("topsecret42"));
    }
}
