//! `luks-hwid-core` : collecte d'identifiants matériels et dérivation de clé
//! à seuil (k parmi n) pour le déverrouillage LUKS sans TPM.
//!
//! Cette crate ne fait aucun appel privilégié : toutes les sources sont
//! injectables (chemins sysfs paramétrables) pour rester testable en unitaire.

#![forbid(unsafe_code)]

pub mod derive;
pub mod error;
pub mod identifier;
pub mod metadata;
pub mod provider;
pub mod providers;
pub mod secret;

mod shamir;

pub use derive::{diagnose, enroll, recover, Diagnosis, Policy, Recovered, ShareDiag, MAX_SHARES};
pub use error::{EnrollError, RecoverError};
pub use identifier::{IdClass, Identifier};
pub use metadata::{EncryptedShare, KdfParams, Metadata, FORMAT_VERSION, TOKEN_TYPE};
pub use provider::{collect_all, default_providers, Provider};
pub use secret::{VolumeSecret, SECRET_LEN};
