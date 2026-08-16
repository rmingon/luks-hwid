use std::fs;
use std::path::PathBuf;

use crate::identifier::{IdClass, Identifier};
use crate::provider::Provider;

/// Numéros de série des barrettes mémoire, lus dans la table SMBIOS brute
/// (structures de type 17, "Memory Device").
pub struct SmbiosRamProvider {
    table_path: PathBuf,
}

impl SmbiosRamProvider {
    pub fn new(table_path: impl Into<PathBuf>) -> Self {
        Self {
            table_path: table_path.into(),
        }
    }

    pub fn system_default() -> Self {
        Self::new("/sys/firmware/dmi/tables/DMI")
    }
}

impl Provider for SmbiosRamProvider {
    fn name(&self) -> &'static str {
        "smbios-ram"
    }

    fn collect(&self) -> Vec<Identifier> {
        let Ok(data) = fs::read(&self.table_path) else {
            return Vec::new();
        };
        parse_type17_serials(&data)
            .iter()
            .filter_map(|s| Identifier::new(IdClass::RamSerial, s))
            .collect()
    }
}

/// Offset du champ "Serial Number" (index de chaîne) dans une structure type 17.
const TYPE17_SERIAL_OFFSET: usize = 0x18;

/// Parcourt la table de structures SMBIOS et retourne les numéros de série
/// des structures type 17. Tolérant : toute incohérence arrête le parcours
/// et retourne ce qui a été collecté jusque-là, jamais de panic.
pub(crate) fn parse_type17_serials(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;

    while i + 4 <= data.len() {
        let stype = data[i];
        let flen = data[i + 1] as usize;
        if flen < 4 || i + flen > data.len() {
            break;
        }
        let formatted = &data[i..i + flen];

        // Zone de chaînes : suite de chaînes NUL-terminées, close par un
        // second NUL ("string-set"). Aucune chaîne = deux NUL consécutifs.
        let mut strings: Vec<String> = Vec::new();
        let mut j = i + flen;
        loop {
            if j >= data.len() {
                break;
            }
            let start = j;
            while j < data.len() && data[j] != 0 {
                j += 1;
            }
            if j >= data.len() {
                // chaîne non terminée : table tronquée
                break;
            }
            if start == j {
                // premier octet déjà NUL : string-set vide (double NUL)
                j += 1;
                if j < data.len() && data[j] == 0 {
                    j += 1;
                }
                break;
            }
            strings.push(String::from_utf8_lossy(&data[start..j]).into_owned());
            j += 1; // NUL de fin de chaîne
            if j < data.len() && data[j] == 0 {
                j += 1; // NUL de fin de string-set
                break;
            }
        }

        if stype == 17 && flen > TYPE17_SERIAL_OFFSET {
            let idx = formatted[TYPE17_SERIAL_OFFSET] as usize;
            if idx >= 1 && idx <= strings.len() {
                out.push(strings[idx - 1].clone());
            }
        }

        if stype == 127 {
            break; // End-of-Table
        }
        if j <= i {
            break; // aucune progression : table corrompue
        }
        i = j;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construit une structure SMBIOS : en-tête + zone formatée + chaînes.
    fn structure(stype: u8, formatted_tail: &[u8], strings: &[&str]) -> Vec<u8> {
        let flen = 4 + formatted_tail.len();
        let mut buf = vec![stype, flen as u8, 0x34, 0x12];
        buf.extend_from_slice(formatted_tail);
        if strings.is_empty() {
            buf.extend_from_slice(&[0, 0]);
        } else {
            for s in strings {
                buf.extend_from_slice(s.as_bytes());
                buf.push(0);
            }
            buf.push(0);
        }
        buf
    }

    /// Type 17 minimal : zone formatée de 0x1B octets, l'octet à l'offset
    /// 0x18 désigne la chaîne du numéro de série (1-indexé, 0 = absent).
    fn type17(serial_index: u8, strings: &[&str]) -> Vec<u8> {
        let mut tail = vec![0u8; 0x1B - 4];
        tail[TYPE17_SERIAL_OFFSET - 4] = serial_index;
        structure(17, &tail, strings)
    }

    #[test]
    fn extrait_les_series_type17() {
        let mut table = Vec::new();
        table.extend(structure(16, &[0u8; 11], &[])); // Physical Memory Array
        table.extend(type17(2, &["DIMM A1", "SN12345678"]));
        table.extend(type17(2, &["DIMM A2", "SN87654321"]));
        table.extend(structure(127, &[], &[])); // End-of-Table

        assert_eq!(
            parse_type17_serials(&table),
            vec!["SN12345678".to_string(), "SN87654321".to_string()]
        );
    }

    #[test]
    fn slot_vide_et_index_zero_ignores() {
        let mut table = Vec::new();
        table.extend(type17(0, &["DIMM B1"])); // pas de numéro de série
        table.extend(type17(9, &["DIMM B2"])); // index hors bornes
        table.extend(structure(127, &[], &[]));
        assert!(parse_type17_serials(&table).is_empty());
    }

    #[test]
    fn table_tronquee_ou_corrompue_sans_panic() {
        let mut table = type17(2, &["DIMM A1", "SN12345678"]);
        table.extend(type17(2, &["DIMM A2", "SNFFFF"]));
        for cut in 0..table.len() {
            let _ = parse_type17_serials(&table[..cut]); // ne doit pas paniquer
        }
        assert!(parse_type17_serials(&[]).is_empty());
        assert!(parse_type17_serials(&[17, 0, 0]).is_empty());
        assert!(parse_type17_serials(&[17, 200, 0, 0, 0]).is_empty());
    }

    #[test]
    fn provider_source_absente_liste_vide() {
        let p = SmbiosRamProvider::new("/nonexistent/dmi/table");
        assert!(p.collect().is_empty());
    }

    #[test]
    fn provider_filtre_les_series_poubelle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("DMI");
        let mut table = Vec::new();
        table.extend(type17(2, &["DIMM A1", "SN12345678"]));
        table.extend(type17(2, &["DIMM A2", "00000000"]));
        table.extend(structure(127, &[], &[]));
        std::fs::write(&path, &table).unwrap();

        let ids = SmbiosRamProvider::new(&path).collect();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].class(), IdClass::RamSerial);
    }
}
