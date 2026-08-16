use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// Longueur du secret de volume : 64 octets aléatoires.
///
/// Ce secret sert de passphrase de keyslot LUKS2 (encodée en hexadécimal
/// pour traverser proprement le contrat keyscript). Ce n'est JAMAIS la
/// master key du volume : le révoquer se fait en tuant son keyslot.
pub const SECRET_LEN: usize = 64;

/// Secret de volume : buffer verrouillé en mémoire (mlock, meilleur effort)
/// et zéroïsé sur tous les chemins de sortie, panics comprises (unwind
/// exécute les Drop).
pub struct VolumeSecret {
    bytes: Box<[u8; SECRET_LEN]>,
    // Déclaré après `bytes` : le munlock a lieu APRÈS la zéroïsation.
    _lock: Option<region::LockGuard>,
}

impl VolumeSecret {
    fn from_box(bytes: Box<[u8; SECRET_LEN]>) -> Self {
        // Échec de mlock (ulimit, environnement exotique) : on continue,
        // le swap est un risque moindre que refuser de booter.
        let lock = region::lock(bytes.as_ptr(), SECRET_LEN).ok();
        VolumeSecret {
            bytes,
            _lock: lock,
        }
    }

    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = Box::new([0u8; SECRET_LEN]);
        rng.fill_bytes(&mut *bytes);
        Self::from_box(bytes)
    }

    /// `None` si la longueur n'est pas exactement `SECRET_LEN`.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != SECRET_LEN {
            return None;
        }
        let mut bytes = Box::new([0u8; SECRET_LEN]);
        bytes.copy_from_slice(slice);
        Some(Self::from_box(bytes))
    }

    /// Accès aux octets bruts. À ne consommer que pour la sortie keyscript
    /// ou l'ajout de keyslot.
    pub fn expose(&self) -> &[u8; SECRET_LEN] {
        &self.bytes
    }

    /// Encodage hexadécimal (128 caractères) : c'est cette forme qui sert
    /// de passphrase LUKS, robuste au transport par pipe.
    pub fn to_hex(&self) -> Zeroizing<String> {
        let mut s = String::with_capacity(SECRET_LEN * 2);
        for b in self.bytes.iter() {
            s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
            s.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble"));
        }
        Zeroizing::new(s)
    }
}

impl Drop for VolumeSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let mut raw = [0u8; SECRET_LEN];
        raw[0] = 0x0f;
        raw[1] = 0xa0;
        raw[63] = 0xff;
        let s = VolumeSecret::from_slice(&raw).unwrap();
        let hex = s.to_hex();
        assert_eq!(hex.len(), 128);
        assert!(hex.starts_with("0fa0"));
        assert!(hex.ends_with("ff"));
    }

    #[test]
    fn from_slice_longueur_stricte() {
        assert!(VolumeSecret::from_slice(&[0u8; 63]).is_none());
        assert!(VolumeSecret::from_slice(&[0u8; 65]).is_none());
        assert!(VolumeSecret::from_slice(&[0u8; 64]).is_some());
    }
}
