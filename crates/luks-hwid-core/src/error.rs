use thiserror::Error;

/// Erreurs d'enrôlement (découpe + chiffrement des parts).
#[derive(Debug, Error)]
pub enum EnrollError {
    #[error("seuil trop bas : k={0}, minimum 2")]
    ThresholdTooLow(u8),

    #[error("identifiants insuffisants : {have} collectés, {need} requis (k)")]
    NotEnoughIdentifiers { have: usize, need: usize },

    #[error("trop d'identifiants : {have}, maximum {max} (taille du token LUKS2)")]
    TooManyIdentifiers { have: usize, max: usize },

    #[error("paramètres Argon2 invalides : {0}")]
    Kdf(String),

    #[error("échec du chiffrement d'une part")]
    Crypto,

    #[error("découpe Shamir : {0}")]
    Shamir(#[from] ShamirError),
}

/// Erreurs de reconstruction au boot.
#[derive(Debug, Error)]
pub enum RecoverError {
    #[error("le token n'est pas de type luks-hwid : {0:?}")]
    WrongTokenType(String),

    #[error("version de format non supportée : {0}")]
    UnsupportedVersion(u32),

    #[error(
        "quorum non atteint : {opened}/{k} parts déchiffrées, parts orphelines : {missing_hints:?}"
    )]
    QuorumNotMet {
        opened: u8,
        k: u8,
        missing_hints: Vec<String>,
    },

    #[error("paramètres KDF invalides ou non supportés : {0}")]
    Kdf(String),

    #[error("métadonnées corrompues : {0}")]
    Corrupt(String),
}

/// Erreurs internes du partage de secret.
#[derive(Debug, Error)]
pub enum ShamirError {
    #[error("paramètres invalides : k={k}, n={n} (2 <= k <= n <= 254 requis)")]
    InvalidParams { k: u8, n: u8 },

    #[error("aucune part fournie")]
    NoShares,

    #[error("abscisse dupliquée dans les parts fournies")]
    DuplicateShare,

    #[error("parts de longueurs différentes")]
    LengthMismatch,
}
