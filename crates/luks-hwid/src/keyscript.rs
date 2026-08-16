//! Pilote du contrat keyscript crypttab : lit les variables CRYPTTAB_*,
//! déroule la machine à états, écrit la clé sur stdout (et rien d'autre),
//! sort non nul en échec pour laisser la saisie manuelle prendre le relais.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use luks_hwid_core::{collect_all, default_providers, Metadata, Policy, MAX_SHARES};
use zeroize::Zeroizing;

use crate::error::{AppError, Result};
use crate::fsm::{step, Action, Ev, St};
use crate::kmsg::Log;
use crate::luks::Luks;
use crate::rescue::RescueUsb;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Contexte matérialisé par le pilote au fil des transitions.
struct Ctx {
    luks: Luks,
    log: Log,
    usb: Option<RescueUsb>,
    token: Option<(u32, Metadata)>,
    fingerprint_key: Option<Zeroizing<String>>,
    rescue_key: Option<Zeroizing<Vec<u8>>>,
}

/// Point d'entrée keyscript. Retourne le code de sortie du processus.
pub fn run() -> u8 {
    let mut log = Log::new();
    match run_inner(&mut log) {
        Ok(()) => 0,
        Err(e) => {
            log.err(&format!("échec : {e}"));
            log.info("saisie manuelle de passphrase possible via cryptsetup");
            1
        }
    }
}

fn run_inner(log: &mut Log) -> Result<()> {
    let device = std::env::var("CRYPTTAB_SOURCE")
        .map_err(|_| AppError::Msg("CRYPTTAB_SOURCE absent : à lancer comme keyscript".into()))?;
    let name = std::env::var("CRYPTTAB_NAME").unwrap_or_else(|_| "?".into());
    let header_opt = std::env::var("CRYPTTAB_OPTION_header").ok();

    log.info(&format!("keyscript pour {name} ({device})"));

    // Résolution du header : attaché (rien à faire), ou détaché. Un header
    // détaché dont le chemin n'existe pas est cherché sur la clé USB.
    let mut usb: Option<RescueUsb> = None;
    let header: Option<PathBuf> = match header_opt {
        None => None,
        Some(p) => {
            let path = PathBuf::from(&p);
            if path.is_file() {
                Some(path)
            } else {
                usb = RescueUsb::find_and_mount(log);
                match usb.as_ref().and_then(|u| u.header()) {
                    Some(h) => {
                        log.info(&format!("header détaché : {}", h.display()));
                        Some(h)
                    }
                    None => {
                        // HeaderMissing : la FSM confirme l'abandon propre.
                        let (_, action) = step(St::Init, Ev::HeaderMissing);
                        debug_assert!(matches!(action, Action::Abort(_)));
                        return Err(AppError::Msg(
                            "header détaché introuvable, clé USB absente".into(),
                        ));
                    }
                }
            }
        }
    };

    let mut ctx = Ctx {
        luks: Luks::new(device, header),
        log: Log::new(),
        usb,
        token: None,
        fingerprint_key: None,
        rescue_key: None,
    };

    let mut st = St::Init;
    let mut ev = Ev::HeaderFound; // le header est résolu ci-dessus
    loop {
        let (next, action) = step(st, ev);
        st = next;
        match action {
            Action::ReadToken => {
                ctx.token = ctx.luks.find_hwid_token()?;
                ev = match &ctx.token {
                    Some((id, meta)) => {
                        ctx.log.info(&format!(
                            "token luks-hwid #{id} : k={} n={}",
                            meta.k,
                            meta.n()
                        ));
                        Ev::TokenFound
                    }
                    None => {
                        ctx.log
                            .info("aucun token luks-hwid : volume vierge ou cloné");
                        Ev::TokenMissing
                    }
                };
            }

            Action::CollectAndRecover => {
                let meta = &ctx.token.as_ref().expect("token chargé").1;
                let ids = collect_all(&default_providers());
                ctx.log
                    .info(&format!("{} identifiants matériels collectés", ids.len()));
                match luks_hwid_core::recover(meta, &ids) {
                    Ok(rec) => {
                        ctx.log.info(&format!(
                            "quorum atteint : {}/{} parts",
                            rec.shares_used, meta.k
                        ));
                        ctx.fingerprint_key = Some(rec.secret.to_hex());
                        ev = Ev::QuorumMet;
                    }
                    Err(e) => {
                        ctx.log.warn(&format!("quorum non atteint : {e}"));
                        ev = Ev::QuorumNotMet;
                    }
                }
            }

            Action::SearchUsb => {
                if ctx.usb.is_none() {
                    ctx.usb = RescueUsb::find_and_mount(&mut ctx.log);
                }
                ev = Ev::UsbKeyAbsentOrInvalid;
                if let Some(usb) = &ctx.usb {
                    if let Some(key) = usb.keyfile().and_then(|kf| fs::read(kf).ok()) {
                        let key = Zeroizing::new(key);
                        if ctx.luks.test_key(&key)? {
                            ctx.log.info("keyfile USB vérifié : il ouvre le volume");
                            ctx.rescue_key = Some(key);
                            ev = Ev::UsbKeyValid;
                        } else {
                            ctx.log
                                .err("keyfile USB présent mais n'ouvre PAS ce volume");
                        }
                    } else {
                        ctx.log.warn("clé USB montée mais sans keyfile de secours");
                    }
                }
            }

            Action::Reenroll => {
                ev = match reenroll(&mut ctx) {
                    Ok(()) => {
                        ctx.log.info("ré-enrôlement terminé");
                        Ev::ReenrollOk
                    }
                    Err(e) => {
                        ctx.log
                            .err(&format!("ré-enrôlement échoué (boot maintenu) : {e}"));
                        Ev::ReenrollFailed
                    }
                };
            }

            Action::EmitFingerprintKey => {
                let key = ctx.fingerprint_key.as_ref().expect("clé reconstruite");
                emit(key.as_bytes())?;
                return Ok(());
            }

            Action::EmitRescueKey => {
                let key = ctx.rescue_key.as_ref().expect("keyfile vérifié");
                emit(key)?;
                return Ok(());
            }

            Action::Abort(reason) => {
                return Err(AppError::Msg(format!("abandon : {reason:?}")));
            }
        }
    }
}

/// La clé, toute la clé, rien que la clé : stdout, sans fin de ligne.
fn emit(key: &[u8]) -> Result<()> {
    let mut out = std::io::stdout().lock();
    out.write_all(key)?;
    out.flush()?;
    Ok(())
}

/// Ré-enrôlement : REMPLACE l'empreinte précédente (LUKS2 est limité à 32
/// keyslots et une empreinte obsolète ne doit pas rester valide).
/// Ordre pensé pour la coupure de courant : au pire moment, il reste DEUX
/// keyslots valides (ancien + nouveau), jamais zéro.
fn reenroll(ctx: &mut Ctx) -> Result<()> {
    let usb = ctx.usb.as_ref().expect("USB montée");
    let keyfile = usb
        .keyfile()
        .ok_or_else(|| AppError::Msg("keyfile disparu".into()))?;
    let keyfile_str = keyfile.to_string_lossy().into_owned();

    // 1. Sauvegarde du header AVANT toute écriture, sur la clé USB si
    //    possible, sinon dans /run (mieux que rien, journalisé).
    let backup_path = if usb.remount_rw(&mut ctx.log) {
        let dir = usb.backup_dir();
        fs::create_dir_all(&dir)?;
        dir.join(format!("header-{}.img", now_unix()))
    } else {
        fs::create_dir_all("/run/luks-hwid")?;
        PathBuf::from(format!("/run/luks-hwid/header-{}.img", now_unix()))
    };
    ctx.luks
        .header_backup(&backup_path.to_string_lossy())?;
    ctx.log.info(&format!(
        "étape 1/6 : header sauvegardé dans {}",
        backup_path.display()
    ));

    // 2. Empreinte de la machine courante.
    let mut ids = collect_all(&default_providers());
    if ids.len() > MAX_SHARES {
        ctx.log.warn(&format!(
            "{} identifiants, troncature à {MAX_SHARES} (les USB excédentaires sont écartés)",
            ids.len()
        ));
        ids.truncate(MAX_SHARES);
    }
    if ids.len() < 2 {
        return Err(AppError::Msg(format!(
            "seulement {} identifiant(s) exploitable(s), enrôlement impossible",
            ids.len()
        )));
    }
    let policy = Policy::default_for(ids.len());
    ctx.log.info(&format!(
        "étape 2/6 : {} identifiants collectés, seuil k={}",
        ids.len(),
        policy.k
    ));

    // 3. Nouveau secret + métadonnées.
    let (secret, mut meta) =
        luks_hwid_core::enroll(&mut rand_core::OsRng, &ids, &policy)?;
    let secret_hex = secret.to_hex();

    // 4. Nouveau keyslot, authentifié par le keyfile USB (qui occupe son
    //    propre keyslot et ne détient jamais la master key).
    let slot = ctx.luks.add_keyslot(&keyfile_str, secret_hex.as_bytes())?;
    ctx.log.info(&format!("étape 3/6 : keyslot {slot} ajouté"));

    // 5. Vérification RÉELLE avant toute révocation.
    if !ctx.luks.test_key(secret_hex.as_bytes())? {
        let _ = ctx.luks.kill_slot(slot, &keyfile_str);
        return Err(AppError::Msg(
            "le nouveau keyslot n'ouvre pas le volume, révoqué".into(),
        ));
    }
    ctx.log
        .info("étape 4/6 : nouveau keyslot vérifié (il ouvre le volume)");

    // 6. Token remplacé, puis seulement ensuite l'ancien slot révoqué.
    meta.keyslots = vec![slot.to_string()];
    meta.created_unix = now_unix();
    ctx.luks.token_import(&meta)?;
    let old = ctx.token.take();
    if let Some((old_id, old_meta)) = old {
        ctx.luks.token_remove(old_id)?;
        ctx.log.info("étape 5/6 : ancien token retiré");
        for s in old_meta.keyslots.iter().filter_map(|s| s.parse::<u32>().ok()) {
            if s != slot {
                ctx.luks.kill_slot(s, &keyfile_str)?;
                ctx.log
                    .info(&format!("étape 6/6 : ancien keyslot {s} révoqué"));
            }
        }
    } else {
        ctx.log
            .info("étapes 5-6/6 : premier enrôlement, rien à révoquer");
    }
    Ok(())
}
