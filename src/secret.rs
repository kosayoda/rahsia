use std::fmt;

use secrecy::SecretString;

/// A single secret entry stored in the vault.
pub struct SecretEntry {
    /// The namespace, or empty string for the default namespace.
    pub namespace: String,

    /// The key name, e.g. `AWS_ACCESS_KEY_ID`.
    pub key: String,

    /// The secret value. Zeroized on drop, redacted in debug output.
    pub value: SecretString,

    /// Tags for grouping/filtering, e.g. `["aws", "prod"]`.
    pub tags: Vec<String>,

    /// When this entry was first created.
    pub created_at: jiff::Timestamp,

    /// When this entry was last modified.
    pub updated_at: jiff::Timestamp,
}

impl SecretEntry {
    pub fn new(namespace: String, key: String, value: SecretString, tags: Vec<String>) -> Self {
        let now = jiff::Timestamp::now();
        Self {
            namespace,
            key,
            value,
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
            .field("namespace", &self.namespace)
            .field("key", &self.key)
            .field("value", &"[REDACTED]")
            .field("tags", &self.tags)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}
