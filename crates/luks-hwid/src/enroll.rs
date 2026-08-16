//! `enroll` : provisionne l'empreinte depuis le système installé, via
//! libcryptsetup (feature `native-luks`, Linux uniquement).
//!
//! Règle absolue : REFUSE de s'exécuter s'il n'existe pas déjà un autre
//! keyslot (passphrase de secours). luks-hwid ne doit jamais être le seul
//! moyen d'ouvrir un volume.

use std::path::PathBuf;

use luks_hwid_core::KdfParams;

#[cfg_attr(
    not(all(target_os = "linux", feature = "native-luks")),
    allow(dead_code)
)]
pub struct EnrollOpts {
    pub device: PathBuf,
    pub header: Option<PathBuf>,
    pub threshold: Option<u8>,
    pub kdf: KdfParams,
}

#[cfg(all(target_os = "linux", feature = "native-luks"))]
mod native {
    use std::time::{SystemTime, UNIX_EPOCH};

    use either::Either;
    use libcryptsetup_rs::consts::flags::CryptActivate;
    use libcryptsetup_rs::consts::vals::{EncryptionFormat, KeyslotInfo};
    use libcryptsetup_rs::{CryptInit, TokenInput};
    use luks_hwid_core::{collect_all, default_providers, Metadata, Policy, MAX_SHARES};
    use zeroize::Zeroizing;

    use super::EnrollOpts;
    use crate::error::{AppError, Result};

    pub fn run(opts: EnrollOpts) -> Result<u8> {
        let mut dev = match &opts.header {
            Some(h) => CryptInit::init_with_data_device(Either::Right((
                h.as_path(),
                opts.device.as_path(),
            ))),
            None => CryptInit::init(opts.device.as_path()),
        }
        .map_err(|e| AppError::Cryptsetup(e.to_string()))?;

        dev.context_handle()
            .load::<()>(Some(EncryptionFormat::Luks2), None)
            .map_err(|e| AppError::Cryptsetup(format!("pas un volume LUKS2 : {e}")))?;

        // Tokens luks-hwid existants (ré-enrôlement depuis l'espace utilisateur).
        let mut old_tokens: Vec<(u32, Metadata)> = Vec::new();
        for t in 0..32u32 {
            if let Ok(v) = dev.token_handle().json_get(t) {
                if let Ok(meta) = Metadata::from_json_value(&v) {
                    old_tokens.push((t, meta));
                }
            }
        }
        let old_hwid_slots: Vec<u32> = old_tokens
            .iter()
            .flat_map(|(_, m)| m.keyslots.iter().filter_map(|s| s.parse().ok()))
            .collect();

        // Keyslots actifs HORS empreinte : la passphrase de secours.
        let mut other_slots = Vec::new();
        for i in 0..32u32 {
            if let Ok(KeyslotInfo::Active | KeyslotInfo::ActiveLast) =
                dev.keyslot_handle().status(i)
            {
                if !old_hwid_slots.contains(&i) {
                    other_slots.push(i);
                }
            }
        }
        if other_slots.is_empty() {
            return Err(AppError::Msg(
                "REFUS : aucun autre keyslot sur ce volume. Ajoutez d'abord une \
                 passphrase de secours (cryptsetup luksAddKey), luks-hwid ne doit \
                 jamais être le seul moyen d'ouvrir un volume."
                    .into(),
            ));
        }

        let pass = Zeroizing::new(
            rpassword::prompt_password("Passphrase existante du volume : ")
                .map_err(AppError::Io)?,
        );
        dev.activate_handle()
            .activate_by_passphrase(None, None, pass.as_bytes(), CryptActivate::empty())
            .map_err(|_| AppError::Msg("passphrase refusée".into()))?;

        // Empreinte de la machine courante.
        let mut ids = collect_all(&default_providers());
        if ids.len() > MAX_SHARES {
            eprintln!(
                "attention : {} identifiants, troncature à {MAX_SHARES}",
                ids.len()
            );
            ids.truncate(MAX_SHARES);
        }
        if ids.len() < 2 {
            return Err(AppError::Msg(format!(
                "seulement {} identifiant(s) matériel(s) exploitable(s) : \
                 impossible de construire un schéma à seuil (il en faut au moins 2). \
                 Lancez la commande en root pour accéder à /sys/class/dmi/id.",
                ids.len()
            )));
        }

        let policy = match opts.threshold {
            Some(k) => Policy {
                k,
                kdf: opts.kdf.clone(),
            },
            None => {
                let mut p = Policy::default_for(ids.len());
                p.kdf = opts.kdf.clone();
                p
            }
        };
        println!(
            "{} identifiants collectés, schéma {} parmi {}",
            ids.len(),
            policy.k,
            ids.len()
        );

        let (secret, mut meta) =
            luks_hwid_core::enroll(&mut rand_core::OsRng, &ids, &policy)?;
        let secret_hex = secret.to_hex();

        // Nouveau keyslot, puis vérification réelle AVANT toute révocation.
        let slot = dev
            .keyslot_handle()
            .add_by_passphrase(None, pass.as_bytes(), secret_hex.as_bytes())
            .map_err(|e| AppError::Cryptsetup(format!("ajout de keyslot : {e}")))?;
        let verified = dev
            .activate_handle()
            .activate_by_passphrase(None, Some(slot), secret_hex.as_bytes(), CryptActivate::empty())
            .is_ok();
        if !verified {
            let _ = dev.keyslot_handle().destroy(slot);
            return Err(AppError::Msg(
                "le nouveau keyslot n'ouvre pas le volume, révoqué".into(),
            ));
        }

        meta.keyslots = vec![slot.to_string()];
        meta.created_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Remplacement : nouveau token d'abord, révocations ensuite.
        let value = meta.to_json_value()?;
        for (t, _) in &old_tokens {
            dev.token_handle()
                .json_set(TokenInput::RemoveToken(*t))
                .map_err(|e| AppError::Cryptsetup(format!("retrait de token : {e}")))?;
        }
        dev.token_handle()
            .json_set(TokenInput::AddToken(&value))
            .map_err(|e| AppError::Cryptsetup(format!("écriture du token : {e}")))?;
        for s in old_hwid_slots {
            if s != slot {
                dev.keyslot_handle()
                    .destroy(s)
                    .map_err(|e| AppError::Cryptsetup(format!("révocation du slot {s} : {e}")))?;
                println!("ancien keyslot d'empreinte {s} révoqué");
            }
        }

        println!("Empreinte enrôlée : keyslot {slot}, token luks-hwid écrit.");
        println!("Vérifiez avec : luks-hwid status --device {}", opts.device.display());
        Ok(0)
    }
}

#[cfg(all(target_os = "linux", feature = "native-luks"))]
pub use native::run;

#[cfg(not(all(target_os = "linux", feature = "native-luks")))]
pub fn run(_opts: EnrollOpts) -> crate::error::Result<u8> {
    Err(crate::error::AppError::Msg(
        "enroll nécessite le build Linux avec la feature `native-luks` \
         (build par défaut : cargo build --release). Le binaire keyscript \
         musl (--no-default-features) n'embarque pas libcryptsetup."
            .into(),
    ))
}
