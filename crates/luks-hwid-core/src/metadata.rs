use serde::{Deserialize, Serialize};

use crate::error::RecoverError;
use crate::identifier::IdClass;

/// Type de token LUKS2 revendiqué par ce projet.
pub const TOKEN_TYPE: &str = "luks-hwid";

/// Version du format des métadonnées. Toute évolution incompatible
/// incrémente cette valeur ; la lecture refuse les versions inconnues.
pub const FORMAT_VERSION: u32 = 1;

/// Paramètres Argon2id, stockés dans le token pour rester ajustables
/// à l'enrôlement sans toucher au binaire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algo: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            algo: "argon2id".to_owned(),
            // 64 MiB : dimensionné pour un initramfs, payé au plus n fois.
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            parallelism: 1,
        }
    }
}

/// Une part Shamir chiffrée par la clé dérivée d'un identifiant.
/// Aucun identifiant en clair : seule l'empreinte tronquée `hint` subsiste.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// Abscisse Shamir (1..=n), reprise dans l'AAD.
    pub idx: u8,
    pub class: IdClass,
    /// Empreinte tronquée de l'identifiant (8 hex), pour le diagnostic
    /// et la présélection au boot.
    pub hint: String,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ct: Vec<u8>,
}

/// Contenu complet du token LUKS2 de type `luks-hwid`.
///
/// `type` et `keyslots` sont exigés par le format de token LUKS2 lui-même ;
/// le reste est le format propre à luks-hwid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(rename = "type")]
    pub token_type: String,
    /// Keyslot(s) LUKS2 ouvert(s) par le secret reconstruit.
    pub keyslots: Vec<String>,
    pub version: u32,
    /// Seuil : nombre de parts nécessaires. n est implicite (shares.len()).
    pub k: u8,
    pub kdf: KdfParams,
    pub cipher: String,
    /// Date d'enrôlement, secondes Unix (pas de dépendance calendrier).
    #[serde(default)]
    pub created_unix: u64,
    pub shares: Vec<EncryptedShare>,
}

impl Metadata {
    pub fn n(&self) -> u8 {
        self.shares.len() as u8
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn to_json_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    /// Désérialise et valide type + version. Les autres invariants sont
    /// contrôlés par `recover`.
    pub fn from_json_str(s: &str) -> Result<Self, RecoverError> {
        let meta: Metadata =
            serde_json::from_str(s).map_err(|e| RecoverError::Corrupt(e.to_string()))?;
        meta.validate_envelope()?;
        Ok(meta)
    }

    pub fn from_json_value(v: &serde_json::Value) -> Result<Self, RecoverError> {
        let meta: Metadata =
            serde_json::from_value(v.clone()).map_err(|e| RecoverError::Corrupt(e.to_string()))?;
        meta.validate_envelope()?;
        Ok(meta)
    }

    fn validate_envelope(&self) -> Result<(), RecoverError> {
        if self.token_type != TOKEN_TYPE {
            return Err(RecoverError::WrongTokenType(self.token_type.clone()));
        }
        if self.version > FORMAT_VERSION {
            return Err(RecoverError::UnsupportedVersion(self.version));
        }
        Ok(())
    }
}

mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Metadata {
        Metadata {
            token_type: TOKEN_TYPE.to_owned(),
            keyslots: vec!["2".to_owned()],
            version: FORMAT_VERSION,
            k: 2,
            kdf: KdfParams::default(),
            cipher: "xchacha20-poly1305".to_owned(),
            created_unix: 1_755_000_000,
            shares: vec![EncryptedShare {
                idx: 1,
                class: IdClass::RamSerial,
                hint: "9f3a1c08".to_owned(),
                salt: vec![1; 16],
                nonce: vec![2; 24],
                ct: vec![3; 80],
            }],
        }
    }

    #[test]
    fn roundtrip_json() {
        let meta = sample();
        let json = meta.to_json_string().unwrap();
        assert!(json.contains("\"type\":\"luks-hwid\""));
        assert!(json.contains("\"class\":\"ram_serial\""));
        let back = Metadata::from_json_str(&json).unwrap();
        assert_eq!(back.k, 2);
        assert_eq!(back.n(), 1);
        assert_eq!(back.shares[0].salt, vec![1; 16]);
    }

    #[test]
    fn refuse_mauvais_type_et_version_future() {
        let mut meta = sample();
        meta.token_type = "systemd-tpm2".to_owned();
        let json = serde_json::to_string(&meta).unwrap();
        assert!(matches!(
            Metadata::from_json_str(&json),
            Err(RecoverError::WrongTokenType(_))
        ));

        let mut meta = sample();
        meta.version = FORMAT_VERSION + 1;
        let json = serde_json::to_string(&meta).unwrap();
        assert!(matches!(
            Metadata::from_json_str(&json),
            Err(RecoverError::UnsupportedVersion(_))
        ));
    }
}
