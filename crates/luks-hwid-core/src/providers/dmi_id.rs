use std::fs;
use std::path::PathBuf;

use crate::identifier::{IdClass, Identifier};
use crate::provider::Provider;

/// Numéro de série de la carte mère et UUID produit, exposés par le noyau
/// dans /sys/class/dmi/id (lecture réservée à root pour les séries).
pub struct DmiIdProvider {
    root: PathBuf,
}

impl DmiIdProvider {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn system_default() -> Self {
        Self::new("/sys/class/dmi/id")
    }
}

impl Provider for DmiIdProvider {
    fn name(&self) -> &'static str {
        "dmi-id"
    }

    fn collect(&self) -> Vec<Identifier> {
        const FILES: &[(&str, IdClass)] = &[
            ("board_serial", IdClass::BoardSerial),
            ("product_uuid", IdClass::ProductUuid),
        ];
        FILES
            .iter()
            .filter_map(|(file, class)| {
                let raw = fs::read_to_string(self.root.join(file)).ok()?;
                Identifier::new(*class, &raw)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lit_serie_et_uuid_et_filtre_les_poubelles() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("board_serial"), "CZC1234ABC\n").unwrap();
        std::fs::write(
            dir.path().join("product_uuid"),
            "03000200-0400-0500-0006-000700080009\n", // UUID de repli, rejeté
        )
        .unwrap();

        let ids = DmiIdProvider::new(dir.path()).collect();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].class(), IdClass::BoardSerial);
    }

    #[test]
    fn source_absente_liste_vide() {
        assert!(DmiIdProvider::new("/nonexistent/dmi/id").collect().is_empty());
    }
}
