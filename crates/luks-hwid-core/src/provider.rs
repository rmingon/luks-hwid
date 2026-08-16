use std::collections::BTreeSet;

use crate::identifier::Identifier;
use crate::providers::{CpuidProvider, DmiIdProvider, SmbiosRamProvider, UsbProvider};

/// Une source d'identifiants matériels.
///
/// Contrat : `collect` ne panique jamais et ne retourne jamais d'erreur.
/// Une source absente, illisible ou vide produit une liste vide.
pub trait Provider {
    fn name(&self) -> &'static str;
    fn collect(&self) -> Vec<Identifier>;
}

/// Les providers du système réel, dans leurs emplacements par défaut.
pub fn default_providers() -> Vec<Box<dyn Provider>> {
    vec![
        Box::new(SmbiosRamProvider::system_default()),
        Box::new(CpuidProvider::new()),
        Box::new(DmiIdProvider::system_default()),
        Box::new(UsbProvider::system_default()),
    ]
}

/// Concatène toutes les sources, déduplique et trie (classe puis valeur) :
/// l'ordre du résultat est déterministe d'un boot à l'autre.
pub fn collect_all(providers: &[Box<dyn Provider>]) -> Vec<Identifier> {
    let mut set = BTreeSet::new();
    for p in providers {
        for id in p.collect() {
            set.insert(id);
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifier::IdClass;

    struct Fake(Vec<Identifier>);
    impl Provider for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn collect(&self) -> Vec<Identifier> {
            self.0.clone()
        }
    }

    #[test]
    fn deduplique_et_trie() {
        let a = Identifier::new(IdClass::UsbDevice, "1d6b:0002:sn1").unwrap();
        let b = Identifier::new(IdClass::RamSerial, "sn-ram").unwrap();
        let providers: Vec<Box<dyn Provider>> = vec![
            Box::new(Fake(vec![a.clone(), b.clone()])),
            Box::new(Fake(vec![a.clone()])),
        ];
        let all = collect_all(&providers);
        assert_eq!(all.len(), 2);
        // RamSerial < UsbDevice dans l'ordre des classes
        assert_eq!(all[0].class(), IdClass::RamSerial);
        assert_eq!(all[1].class(), IdClass::UsbDevice);
    }
}
