use std::fs;
use std::path::{Path, PathBuf};

use crate::identifier::{canonicalize, IdClass, Identifier};
use crate::provider::Provider;

/// Périphériques USB porteurs d'un numéro de série, via
/// /sys/bus/usb/devices/*/{idVendor,idProduct,serial}.
///
/// Les périphériques sans numéro de série sont ignorés : deux exemplaires
/// du même modèle seraient indistinguables et n'identifient pas la machine.
pub struct UsbProvider {
    root: PathBuf,
}

impl UsbProvider {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn system_default() -> Self {
        Self::new("/sys/bus/usb/devices")
    }

    fn read_attr(dir: &Path, name: &str) -> Option<String> {
        let raw = fs::read_to_string(dir.join(name)).ok()?;
        let v = raw.trim().to_lowercase();
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }
}

impl Provider for UsbProvider {
    fn name(&self) -> &'static str {
        "usb"
    }

    fn collect(&self) -> Vec<Identifier> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            // Les interfaces (ex: "1-1:1.0") n'ont pas d'identité propre.
            if name.to_string_lossy().contains(':') {
                continue;
            }
            let dir = entry.path();
            let Some(vid) = Self::read_attr(&dir, "idVendor") else {
                continue;
            };
            let Some(pid) = Self::read_attr(&dir, "idProduct") else {
                continue;
            };
            let Some(serial_raw) = Self::read_attr(&dir, "serial") else {
                continue;
            };
            // Le numéro de série est filtré seul : un "0123456789" ne doit
            // pas passer sous prétexte que vid:pid le rend unique en surface.
            let Some(serial) = canonicalize(&serial_raw) else {
                continue;
            };
            let value = format!("{vid}:{pid}:{serial}");
            if let Some(id) = Identifier::new(IdClass::UsbDevice, &value) {
                out.push(id);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkdev(root: &Path, name: &str, vid: &str, pid: &str, serial: Option<&str>) {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("idVendor"), format!("{vid}\n")).unwrap();
        fs::write(dir.join("idProduct"), format!("{pid}\n")).unwrap();
        if let Some(s) = serial {
            fs::write(dir.join("serial"), format!("{s}\n")).unwrap();
        }
    }

    #[test]
    fn collecte_uniquement_les_series_exploitables() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        mkdev(root, "1-1", "0951", "1666", Some("AA04012700013021")); // ok
        mkdev(root, "1-2", "046d", "c31c", None); // sans série : ignoré
        mkdev(root, "1-3", "abcd", "0001", Some("0123456789")); // poubelle
        fs::create_dir_all(root.join("1-1:1.0")).unwrap(); // interface

        let ids = UsbProvider::new(root).collect();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].class(), IdClass::UsbDevice);
    }

    #[test]
    fn source_absente_liste_vide() {
        assert!(UsbProvider::new("/nonexistent/usb").collect().is_empty());
    }
}
