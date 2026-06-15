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

    #[error("{context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },

    #[error("vault data is corrupted or incompatible")]
    Serialization(#[from] serde_json::Error),

    #[error("database error: {0}")]
    Database(String),
}

impl Error {
    pub fn io(source: std::io::Error, context: impl Into<String>) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
