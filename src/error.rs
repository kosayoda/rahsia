use camino::Utf8PathBuf;

/// Errors that can occur in rahsia vault operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vault already exists at {0}")]
    VaultAlreadyExists(Utf8PathBuf),

    #[error("vault not found at {0}")]
    VaultNotFound(Utf8PathBuf),

    #[error("incorrect vault password or corrupted vault")]
    BadPassword,

    #[error("secret not found: {0}")]
    SecretNotFound(String),

    #[error("invalid vault file format")]
    InvalidFormat,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, Error>;
