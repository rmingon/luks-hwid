//! Dérivation à seuil : un secret aléatoire est découpé en parts Shamir,
//! chaque part est chiffrée (XChaCha20-Poly1305) par une clé Argon2id
//! dérivée d'UN identifiant matériel. Au boot, k parts déchiffrées
//! suffisent ; un composant changé ne casse rien tant que le quorum tient.

use std::collections::HashMap;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{EnrollError, RecoverError};
use crate::identifier::{IdClass, Identifier};
use crate::metadata::{EncryptedShare, KdfParams, Metadata, FORMAT_VERSION, TOKEN_TYPE};
use crate::secret::{VolumeSecret, SECRET_LEN};
use crate::shamir;

/// Borne haute du nombre de parts : garde le token dans la zone JSON LUKS2
/// (12 KiB par défaut, partagée avec le reste des métadonnées).
pub const MAX_SHARES: usize = 24;

pub const CIPHER: &str = "xchacha20-poly1305";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Politique d'enrôlement.
#[derive(Debug, Clone)]
pub struct Policy {
    pub k: u8,
    pub kdf: KdfParams,
}

impl Policy {
    /// Seuil par défaut : k = max(2, n-1). Tolère le remplacement d'un
    /// composant, jamais moins de deux facteurs.
    pub fn default_for(n: usize) -> Self {
        let k = std::cmp::max(2, n.saturating_sub(1)) as u8;
        Policy {
            k,
            kdf: KdfParams::default(),
        }
    }
}

fn share_key(
    id: &Identifier,
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, String> {
    if kdf.algo != "argon2id" {
        return Err(format!("algo KDF non supporté : {}", kdf.algo));
    }
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.parallelism, Some(32))
        .map_err(|e| e.to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&id.kdf_input(), salt, &mut out[..])
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// AAD liant chaque part à la version du format, sa classe et son abscisse :
/// interdit le mélange de parts entre tokens ou entre positions.
fn aad(version: u32, class: IdClass, idx: u8) -> String {
    format!("luks-hwid:v{version}:{class}:{idx}")
}

/// Génère un secret neuf et le protège par les identifiants fournis.
///
/// Retourne le secret (à enrôler comme passphrase de keyslot, forme hex)
/// et les métadonnées à écrire dans le token LUKS2. `keyslots` et
/// `created_unix` sont laissés à l'appelant.
pub fn enroll(
    rng: &mut (impl RngCore + CryptoRng),
    identifiers: &[Identifier],
    policy: &Policy,
) -> Result<(VolumeSecret, Metadata), EnrollError> {
    let n = identifiers.len();
    if policy.k < 2 {
        return Err(EnrollError::ThresholdTooLow(policy.k));
    }
    if n < policy.k as usize {
        return Err(EnrollError::NotEnoughIdentifiers {
            have: n,
            need: policy.k as usize,
        });
    }
    if n > MAX_SHARES {
        return Err(EnrollError::TooManyIdentifiers {
            have: n,
            max: MAX_SHARES,
        });
    }

    let secret = VolumeSecret::generate(rng);
    let raw_shares = shamir::split(secret.expose(), policy.k, n as u8, rng)?;

    let mut shares = Vec::with_capacity(n);
    for (id, (idx, plain)) in identifiers.iter().zip(raw_shares.iter()) {
        let mut salt = vec![0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce = vec![0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let key = share_key(id, &salt, &policy.kdf).map_err(EnrollError::Kdf)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| EnrollError::Crypto)?;
        let aad = aad(FORMAT_VERSION, id.class(), *idx);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain[..],
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| EnrollError::Crypto)?;

        shares.push(EncryptedShare {
            idx: *idx,
            class: id.class(),
            hint: id.hint(),
            salt,
            nonce,
            ct,
        });
    }

    let meta = Metadata {
        token_type: TOKEN_TYPE.to_owned(),
        keyslots: Vec::new(),
        version: FORMAT_VERSION,
        k: policy.k,
        kdf: policy.kdf.clone(),
        cipher: CIPHER.to_owned(),
        created_unix: 0,
        shares,
    };
    Ok((secret, meta))
}

/// Résultat d'une reconstruction réussie.
pub struct Recovered {
    pub secret: VolumeSecret,
    pub shares_used: u8,
    pub shares_total: u8,
}

/// Recollecte -> déchiffrement des parts disponibles -> reconstruction.
///
/// La présélection se fait par `hint` (comparaison bon marché), la preuve
/// par l'AEAD : une part ne s'ouvre qu'avec l'identifiant exact. Le calcul
/// s'arrête dès que k parts sont ouvertes.
pub fn recover(meta: &Metadata, identifiers: &[Identifier]) -> Result<Recovered, RecoverError> {
    if meta.token_type != TOKEN_TYPE {
        return Err(RecoverError::WrongTokenType(meta.token_type.clone()));
    }
    if meta.version > FORMAT_VERSION {
        return Err(RecoverError::UnsupportedVersion(meta.version));
    }
    if meta.cipher != CIPHER {
        return Err(RecoverError::Corrupt(format!(
            "chiffrement non supporté : {}",
            meta.cipher
        )));
    }
    if meta.k < 2 || meta.shares.is_empty() {
        return Err(RecoverError::Corrupt("k ou parts invalides".to_owned()));
    }

    let mut by_hint: HashMap<String, Vec<&Identifier>> = HashMap::new();
    for id in identifiers {
        by_hint.entry(id.hint()).or_default().push(id);
    }

    let mut opened: Vec<(u8, Zeroizing<Vec<u8>>)> = Vec::new();
    for share in &meta.shares {
        if opened.len() >= meta.k as usize {
            break;
        }
        let Some(candidates) = by_hint.get(&share.hint) else {
            continue;
        };
        for id in candidates.iter().filter(|id| id.class() == share.class) {
            let key = match share_key(id, &share.salt, &meta.kdf) {
                Ok(k) => k,
                Err(e) => return Err(RecoverError::Kdf(e)),
            };
            let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&key[..]) else {
                continue;
            };
            let aad = aad(meta.version, share.class, share.idx);
            match cipher.decrypt(
                XNonce::from_slice(&share.nonce),
                Payload {
                    msg: &share.ct[..],
                    aad: aad.as_bytes(),
                },
            ) {
                Ok(plain) => {
                    opened.push((share.idx, Zeroizing::new(plain)));
                    break;
                }
                Err(_) => continue, // collision de hint ou part obsolète
            }
        }
    }

    if opened.len() < meta.k as usize {
        let opened_idx: Vec<u8> = opened.iter().map(|(x, _)| *x).collect();
        let missing_hints = meta
            .shares
            .iter()
            .filter(|s| !opened_idx.contains(&s.idx))
            .map(|s| format!("{}:{}", s.class, s.hint))
            .collect();
        return Err(RecoverError::QuorumNotMet {
            opened: opened.len() as u8,
            k: meta.k,
            missing_hints,
        });
    }

    let refs: Vec<(u8, &[u8])> = opened.iter().map(|(x, y)| (*x, &y[..])).collect();
    let secret_bytes = shamir::reconstruct(&refs)
        .map_err(|e| RecoverError::Corrupt(e.to_string()))?;
    if secret_bytes.len() != SECRET_LEN {
        return Err(RecoverError::Corrupt(format!(
            "secret reconstruit de longueur {} au lieu de {SECRET_LEN}",
            secret_bytes.len()
        )));
    }
    let secret = VolumeSecret::from_slice(&secret_bytes)
        .ok_or_else(|| RecoverError::Corrupt("longueur de secret".to_owned()))?;

    Ok(Recovered {
        secret,
        shares_used: opened.len() as u8,
        shares_total: meta.n(),
    })
}

/// État d'une part vis-à-vis du matériel courant (sans coût Argon2 :
/// la correspondance se fait sur l'empreinte tronquée).
#[derive(Debug, Clone)]
pub struct ShareDiag {
    pub idx: u8,
    pub class: IdClass,
    pub hint: String,
    pub available: bool,
}

#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub k: u8,
    pub n: u8,
    pub available: u8,
    pub quorum_ok: bool,
    /// available - k : marge avant perte du quorum.
    pub margin: i16,
    pub shares: Vec<ShareDiag>,
    /// Identifiants présents sur la machine mais absents du token.
    pub unenrolled: Vec<(IdClass, String)>,
}

pub fn diagnose(meta: &Metadata, identifiers: &[Identifier]) -> Diagnosis {
    let current_hints: Vec<(IdClass, String)> =
        identifiers.iter().map(|id| (id.class(), id.hint())).collect();

    let shares: Vec<ShareDiag> = meta
        .shares
        .iter()
        .map(|s| ShareDiag {
            idx: s.idx,
            class: s.class,
            hint: s.hint.clone(),
            available: current_hints
                .iter()
                .any(|(c, h)| *c == s.class && *h == s.hint),
        })
        .collect();

    let available = shares.iter().filter(|s| s.available).count() as u8;
    let unenrolled = current_hints
        .into_iter()
        .filter(|(c, h)| {
            !meta
                .shares
                .iter()
                .any(|s| s.class == *c && s.hint == *h)
        })
        .collect();

    Diagnosis {
        k: meta.k,
        n: meta.n(),
        available,
        quorum_ok: available >= meta.k,
        margin: available as i16 - meta.k as i16,
        shares,
        unenrolled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::tests::TestRng;

    fn fast_kdf() -> KdfParams {
        KdfParams {
            algo: "argon2id".to_owned(),
            m_cost_kib: 8,
            t_cost: 1,
            parallelism: 1,
        }
    }

    fn ids() -> Vec<Identifier> {
        vec![
            Identifier::new(IdClass::RamSerial, "SN-RAM-A1").unwrap(),
            Identifier::new(IdClass::RamSerial, "SN-RAM-A2").unwrap(),
            Identifier::new(IdClass::Cpu, "genuineintel;fms=000806ea").unwrap(),
            Identifier::new(IdClass::BoardSerial, "CZC1234ABC").unwrap(),
        ]
    }

    fn policy(k: u8) -> Policy {
        Policy {
            k,
            kdf: fast_kdf(),
        }
    }

    #[test]
    fn enrole_puis_reconstruit_avec_tout_le_materiel() {
        let mut rng = TestRng(1);
        let ids = ids();
        let (secret, meta) = enroll(&mut rng, &ids, &policy(3)).unwrap();
        assert_eq!(meta.n(), 4);
        assert_eq!(meta.k, 3);

        let rec = recover(&meta, &ids).unwrap();
        assert_eq!(rec.secret.expose(), secret.expose());
        assert_eq!(rec.shares_used, 3, "s'arrête dès le quorum");
    }

    #[test]
    fn tolere_un_composant_change_mais_pas_deux() {
        let mut rng = TestRng(2);
        let ids = ids();
        let (secret, meta) = enroll(&mut rng, &ids, &policy(3)).unwrap();

        // Une barrette remplacée : quorum encore atteint (3/4 restants).
        let mut one_changed = ids.clone();
        one_changed[0] = Identifier::new(IdClass::RamSerial, "SN-RAM-NEUVE").unwrap();
        let rec = recover(&meta, &one_changed).unwrap();
        assert_eq!(rec.secret.expose(), secret.expose());

        // Deux composants changés : 2/4 < k=3, quorum perdu.
        let mut two_changed = one_changed.clone();
        two_changed[3] = Identifier::new(IdClass::BoardSerial, "AUTRE-CARTE").unwrap();
        let err = recover(&meta, &two_changed)
            .err()
            .expect("le quorum devait être perdu");
        match err {
            RecoverError::QuorumNotMet {
                opened,
                k,
                missing_hints,
            } => {
                assert_eq!(opened, 2);
                assert_eq!(k, 3);
                assert_eq!(missing_hints.len(), 2);
            }
            other => panic!("attendu QuorumNotMet, obtenu {other:?}"),
        }
    }

    #[test]
    fn le_json_ne_contient_aucune_valeur_d_identifiant() {
        let mut rng = TestRng(3);
        let ids = ids();
        let (_, meta) = enroll(&mut rng, &ids, &policy(2)).unwrap();
        let json = meta.to_json_string().unwrap().to_lowercase();
        for needle in ["sn-ram-a1", "sn-ram-a2", "czc1234abc", "genuineintel"] {
            assert!(!json.contains(needle), "fuite de {needle} dans le token");
        }
    }

    #[test]
    fn part_alteree_ignoree_grace_a_l_aead() {
        let mut rng = TestRng(4);
        let ids = ids();
        let (secret, mut meta) = enroll(&mut rng, &ids, &policy(3)).unwrap();
        meta.shares[0].ct[0] ^= 0xff;
        // La part 1 ne s'ouvre plus mais 3 autres suffisent.
        let rec = recover(&meta, &ids).unwrap();
        assert_eq!(rec.secret.expose(), secret.expose());
    }

    #[test]
    fn refuse_moins_de_k_identifiants_et_seuil_trop_bas() {
        let mut rng = TestRng(5);
        let ids = ids();
        assert!(matches!(
            enroll(&mut rng, &ids[..2], &policy(3)),
            Err(EnrollError::NotEnoughIdentifiers { .. })
        ));
        assert!(matches!(
            enroll(&mut rng, &ids, &policy(1)),
            Err(EnrollError::ThresholdTooLow(1))
        ));
    }

    #[test]
    fn diagnostic_compte_disponibles_orphelines_et_nouveaux() {
        let mut rng = TestRng(6);
        let ids = ids();
        let (_, meta) = enroll(&mut rng, &ids, &policy(3)).unwrap();

        let mut changed = ids.clone();
        changed[0] = Identifier::new(IdClass::RamSerial, "SN-RAM-NEUVE").unwrap();
        let d = diagnose(&meta, &changed);
        assert_eq!(d.n, 4);
        assert_eq!(d.available, 3);
        assert!(d.quorum_ok);
        assert_eq!(d.margin, 0);
        assert_eq!(d.shares.iter().filter(|s| !s.available).count(), 1);
        assert_eq!(d.unenrolled.len(), 1, "la barrette neuve est non enrôlée");
    }

    #[test]
    fn politique_par_defaut() {
        assert_eq!(Policy::default_for(4).k, 3);
        assert_eq!(Policy::default_for(2).k, 2);
        assert_eq!(Policy::default_for(10).k, 9);
    }
}
