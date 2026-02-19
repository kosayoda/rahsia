use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// A single secret entry stored in the vault.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// The key name, e.g. `AWS_ACCESS_KEY_ID`.
    pub key: String,

    /// The secret value. Zeroized on drop, redacted in debug output.
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub value: SecretString,

    /// Tags for grouping/filtering, e.g. `["aws", "prod"]`.
    pub tags: Vec<String>,

    /// When this entry was first created.
    pub created_at: jiff::Timestamp,

    /// When this entry was last modified.
    pub updated_at: jiff::Timestamp,
}

impl SecretEntry {
    pub fn new(key: String, value: String, tags: Vec<String>) -> Self {
        let now = jiff::Timestamp::now();
        Self {
            key,
            value: value.into(),
            tags,
            created_at: now,
            updated_at: now,
        }
    }

    /// Returns true if this entry has the given tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

/// Redact the secret value in debug output.
impl fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretEntry")
            .field("key", &self.key)
            .field("value", &"[REDACTED]")
            .field("tags", &self.tags)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

fn serialize_secret<S: serde::Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    secret.expose_secret().serialize(serializer)
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretString, D::Error> {
    String::deserialize(deserializer).map(SecretString::from)
}
