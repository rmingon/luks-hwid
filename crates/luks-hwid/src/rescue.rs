//! Clé USB de secours : découverte par étiquette de système de fichiers,
//! montage, accès au keyfile et au header détaché.
//!
//! Convention sur la clé (documentée dans le README) :
//!   étiquette FS        LUKSHWID
//!   keyfile             luks-hwid/rescue.key
//!   header détaché      luks-hwid/header.img
//!   sauvegardes         luks-hwid/backup/

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::kmsg::Log;

pub const LABEL: &str = "LUKSHWID";
pub const MOUNTPOINT: &str = "/run/luks-hwid/usb";
pub const KEYFILE_REL: &str = "luks-hwid/rescue.key";
pub const HEADER_REL: &str = "luks-hwid/header.img";
pub const BACKUP_DIR_REL: &str = "luks-hwid/backup";

/// Délai d'attente de l'énumération USB au boot (les clés lentes existent).
pub const USB_TIMEOUT: Duration = Duration::from_secs(10);

pub struct RescueUsb {
    pub mountpoint: PathBuf,
}

impl RescueUsb {
    /// Attend l'apparition de /dev/disk/by-label/LUKSHWID puis monte la clé
    /// en lecture seule (nosuid, nodev). `None` si absente après le délai.
    pub fn find_and_mount(log: &mut Log) -> Option<RescueUsb> {
        let by_label = Path::new("/dev/disk/by-label").join(LABEL);
        let deadline = Instant::now() + USB_TIMEOUT;
        while !by_label.exists() {
            if Instant::now() >= deadline {
                log.info(&format!("aucune clé USB étiquetée {LABEL} détectée"));
                return None;
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        let mnt = PathBuf::from(MOUNTPOINT);
        if fs::create_dir_all(&mnt).is_err() {
            log.err("impossible de créer le point de montage");
            return None;
        }
        let status = Command::new("mount")
            .arg("-o")
            .arg("ro,nosuid,nodev")
            .arg(&by_label)
            .arg(&mnt)
            .status();
        match status {
            Ok(s) if s.success() => {
                log.info(&format!("clé USB {LABEL} montée sur {MOUNTPOINT}"));
                Some(RescueUsb { mountpoint: mnt })
            }
            _ => {
                log.err(&format!("échec du montage de la clé USB {LABEL}"));
                None
            }
        }
    }

    /// Repasse la clé en lecture-écriture (pour y déposer la sauvegarde de
    /// header). Meilleur effort : `false` si refusé.
    pub fn remount_rw(&self, log: &mut Log) -> bool {
        let ok = Command::new("mount")
            .arg("-o")
            .arg("remount,rw")
            .arg(&self.mountpoint)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            log.warn("clé USB non repassable en écriture, sauvegarde du header ailleurs");
        }
        ok
    }

    pub fn keyfile(&self) -> Option<PathBuf> {
        let p = self.mountpoint.join(KEYFILE_REL);
        p.is_file().then_some(p)
    }

    pub fn header(&self) -> Option<PathBuf> {
        let p = self.mountpoint.join(HEADER_REL);
        p.is_file().then_some(p)
    }

    pub fn backup_dir(&self) -> PathBuf {
        self.mountpoint.join(BACKUP_DIR_REL)
    }
}
