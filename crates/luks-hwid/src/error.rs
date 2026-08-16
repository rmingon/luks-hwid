use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("cryptsetup : {0}")]
    Cryptsetup(String),

    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON : {0}")]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Enroll(#[from] luks_hwid_core::EnrollError),

    #[error(transparent)]
    Recover(#[from] luks_hwid_core::RecoverError),

    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
