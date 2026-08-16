//! Opérations LUKS2 du chemin de boot, via le binaire `cryptsetup` déjà
//! embarqué dans l'initramfs par cryptsetup-initramfs / dracut.
//!
//! Le build système (feature `native-luks`) utilise libcryptsetup pour
//! `enroll` ; ici, tout passe par le CLI pour que le keyscript reste un
//! binaire musl statique sans dépendance à la chaîne libcryptsetup.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use luks_hwid_core::Metadata;

use crate::error::{AppError, Result};

pub const MAX_SLOTS: u32 = 32;

pub struct Luks {
    pub device: PathBuf,
    /// Header détaché : ajouté en `--header` à chaque commande.
    pub header: Option<PathBuf>,
}

impl Luks {
    pub fn new(device: impl Into<PathBuf>, header: Option<PathBuf>) -> Self {
        Luks {
            device: device.into(),
            header,
        }
    }

    fn run(&self, args: &[&str], stdin_data: Option<&[u8]>) -> Result<std::process::Output> {
        let mut cmd = Command::new("cryptsetup");
        cmd.arg("-q");
        if let Some(h) = &self.header {
            cmd.arg("--header").arg(h);
        }
        cmd.args(args);
        cmd.stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        if let Some(data) = stdin_data {
            let mut stdin = child.stdin.take().expect("stdin piped");
            stdin.write_all(data)?;
            drop(stdin); // EOF explicite
        }
        Ok(child.wait_with_output()?)
    }

    fn run_ok(&self, args: &[&str], stdin_data: Option<&[u8]>) -> Result<String> {
        let out = self.run(args, stdin_data)?;
        if !out.status.success() {
            return Err(AppError::Cryptsetup(format!(
                "cryptsetup {} : {}",
                args.first().unwrap_or(&"?"),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn dev(&self) -> &str {
        self.device.to_str().unwrap_or("/dev/null")
    }

    /// Cherche le premier token de type luks-hwid. `Ok(None)` = volume sans
    /// empreinte connue (vierge ou cloné).
    pub fn find_hwid_token(&self) -> Result<Option<(u32, Metadata)>> {
        for id in 0..MAX_SLOTS {
            let out = self.run(
                &["token", "export", "--token-id", &id.to_string(), self.dev()],
                None,
            )?;
            if !out.status.success() {
                continue; // slot de token vide
            }
            let json = String::from_utf8_lossy(&out.stdout);
            if let Ok(meta) = Metadata::from_json_str(&json) {
                return Ok(Some((id, meta)));
            }
        }
        Ok(None)
    }

    /// Vérifie qu'une clé ouvre réellement le volume, sans l'activer.
    pub fn test_key(&self, key: &[u8]) -> Result<bool> {
        let out = self.run(
            &["open", "--test-passphrase", "--key-file", "-", self.dev()],
            Some(key),
        )?;
        Ok(out.status.success())
    }

    /// Keyslots occupés, d'après le dump JSON des métadonnées LUKS2.
    pub fn used_keyslots(&self) -> Result<Vec<u32>> {
        let json = self.run_ok(&["luksDump", "--dump-json-metadata", self.dev()], None)?;
        let v: serde_json::Value = serde_json::from_str(&json)?;
        let mut slots: Vec<u32> = v
            .get("keyslots")
            .and_then(|k| k.as_object())
            .map(|o| o.keys().filter_map(|k| k.parse().ok()).collect())
            .unwrap_or_default();
        slots.sort_unstable();
        Ok(slots)
    }

    /// Ajoute `new_key` dans le premier keyslot libre, en s'authentifiant
    /// avec `existing_keyfile`. Retourne le numéro du slot choisi.
    pub fn add_keyslot(&self, existing_keyfile: &str, new_key: &[u8]) -> Result<u32> {
        let used = self.used_keyslots()?;
        let slot = (0..MAX_SLOTS)
            .find(|s| !used.contains(s))
            .ok_or_else(|| AppError::Msg("aucun keyslot LUKS2 libre".to_owned()))?;
        self.run_ok(
            &[
                "luksAddKey",
                "--key-file",
                existing_keyfile,
                "--new-key-slot",
                &slot.to_string(),
                self.dev(),
                "-",
            ],
            Some(new_key),
        )?;
        Ok(slot)
    }

    /// Révoque un keyslot, en s'authentifiant avec le keyfile de secours.
    pub fn kill_slot(&self, slot: u32, auth_keyfile: &str) -> Result<()> {
        self.run_ok(
            &[
                "luksKillSlot",
                "--key-file",
                auth_keyfile,
                self.dev(),
                &slot.to_string(),
            ],
            None,
        )?;
        Ok(())
    }

    /// Sauvegarde du header. Obligatoire AVANT toute écriture de ré-enrôlement.
    pub fn header_backup(&self, dest: &str) -> Result<()> {
        self.run_ok(
            &["luksHeaderBackup", self.dev(), "--header-backup-file", dest],
            None,
        )?;
        Ok(())
    }

    pub fn token_import(&self, meta: &Metadata) -> Result<()> {
        let json = meta.to_json_string()?;
        self.run_ok(&["token", "import", self.dev()], Some(json.as_bytes()))?;
        Ok(())
    }

    pub fn token_remove(&self, id: u32) -> Result<()> {
        self.run_ok(
            &["token", "remove", "--token-id", &id.to_string(), self.dev()],
            None,
        )?;
        Ok(())
    }
}
