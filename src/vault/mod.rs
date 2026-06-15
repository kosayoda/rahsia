pub mod crypto;
pub mod store;

use camino::{Utf8Path, Utf8PathBuf};
use indexmap::IndexMap;
use secrecy::SecretString;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::secret::SecretEntry;

/// An unlocked vault holding secrets in memory.
///
/// The derived encryption key is held in memory for the lifetime of the vault,
/// avoiding repeated key derivation on every save. The key is zeroized on drop.
pub struct Vault {
    path: Utf8PathBuf,
    salt: [u8; 16],
    key: [u8; 32],
    entries: IndexMap<String, SecretEntry>,
}

impl Vault {
    /// Create a new vault at `path`, encrypted with `password`.
    ///
    /// Returns an error if a vault already exists at the path.
    pub fn create(path: &Utf8Path, password: &[u8]) -> Result<Self> {
        if path.exists() {
            return Err(Error::VaultAlreadyExists(path.to_owned()));
        }

        let salt = crypto::generate_salt();
        let key = crypto::derive_key(password, &salt)?;
        let vault = Self {
            path: path.to_owned(),
            salt,
            key,
            entries: IndexMap::new(),
        };

        vault.save()?;
        Ok(vault)
    }

    /// Open an existing vault, decrypting it with `password`.
    pub fn open(path: &Utf8Path, password: &[u8]) -> Result<Self> {
        let (salt, encrypted) = store::read_vault_file(path)?;

        let key = crypto::derive_key(password, &salt)?;
        let mut plaintext = crypto::decrypt(&encrypted, &key)?;
        let entries = serde_json::from_slice(&plaintext);
        plaintext.zeroize();
        let mut entries: IndexMap<String, SecretEntry> = entries?;
        entries.sort_keys();

        Ok(Self {
            path: path.to_owned(),
            salt,
            key,
            entries,
        })
    }

    /// Encrypt and save the vault to disk.
    pub fn save(&self) -> Result<()> {
        let mut plaintext = serde_json::to_vec(&self.entries)?;
        let result = crypto::encrypt(&plaintext, &self.key);
        plaintext.zeroize();
        let encrypted = result?;
        store::write_vault_file(&self.path, &self.salt, &encrypted)?;
        Ok(())
    }

    /// Set a secret. If the key already exists, its value and tags are updated.
    pub fn set(&mut self, key: String, value: SecretString, tags: Vec<String>) {
        match self.entries.get_mut(&key) {
            Some(existing) => {
                existing.value = value;
                existing.tags = tags;
                existing.updated_at = jiff::Timestamp::now();
            }
            None => {
                let entry = SecretEntry::new(key.clone(), value, tags);
                self.entries.insert(key, entry);
                self.entries.sort_keys();
            }
        }
    }

    /// Get a secret entry by key.
    pub fn get(&self, key: &str) -> Result<&SecretEntry> {
        self.entries
            .get(key)
            .ok_or_else(|| Error::SecretNotFound(key.to_string()))
    }

    /// Remove a secret by key.
    pub fn remove(&mut self, key: &str) -> Result<SecretEntry> {
        self.entries
            .shift_remove(key)
            .ok_or_else(|| Error::SecretNotFound(key.to_string()))
    }

    /// Remove multiple secrets by key. Returns the removed entries.
    pub fn remove_many(&mut self, keys: &[String]) -> Vec<SecretEntry> {
        keys.iter()
            .filter_map(|k| self.entries.shift_remove(k))
            .collect()
    }

    /// Rename a secret from `old` to `new`.
    ///
    /// Preserves the value, tags, and creation timestamp. Updates the key name
    /// and `updated_at`. If `new` already exists, it is overwritten.
    pub fn rename(&mut self, old: &str, new: String) -> Result<()> {
        let mut entry = self
            .entries
            .shift_remove(old)
            .ok_or_else(|| Error::SecretNotFound(old.to_string()))?;
        entry.key = new.clone();
        entry.updated_at = jiff::Timestamp::now();
        self.entries.insert(new, entry);
        self.entries.sort_keys();
        Ok(())
    }

    /// List all secret entries, optionally filtered by tag.
    pub fn list(&self, tag: Option<&str>) -> Vec<&SecretEntry> {
        self.entries
            .values()
            .filter(|e| match tag {
                Some(t) => e.has_tag(t),
                None => true,
            })
            .collect()
    }

    /// Add one or more tags to an existing secret.
    pub fn tag(&mut self, key: &str, tags: Vec<String>) -> Result<()> {
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| Error::SecretNotFound(key.to_string()))?;

        for tag in tags {
            if !entry.tags.contains(&tag) {
                entry.tags.push(tag);
                entry.updated_at = jiff::Timestamp::now();
            }
        }

        Ok(())
    }

    /// Remove a tag from an existing secret.
    pub fn untag(&mut self, key: &str, tags: &[String]) -> Result<()> {
        let entry = self
            .entries
            .get_mut(key)
            .ok_or_else(|| Error::SecretNotFound(key.to_string()))?;

        entry.tags.retain(|t| !tags.contains(t));
        entry.updated_at = jiff::Timestamp::now();

        Ok(())
    }

    /// Get all unique tags across all entries.
    pub fn tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .entries
            .values()
            .flat_map(|e| e.tags.iter().cloned())
            .collect();
        tags.sort();
        tags.dedup();
        tags
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        crypto::zeroize_key(&mut self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn test_vault(dir: &std::path::Path) -> (Utf8PathBuf, &[u8]) {
        let dir: &Utf8Path = dir.try_into().unwrap();
        let path = dir.join("test.vault");
        let password = b"test-password";
        (path, password)
    }

    #[test]
    fn create_and_reopen_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let vault = Vault::create(&path, password).unwrap();
        assert!(vault.list(None).is_empty());
        drop(vault);

        let vault = Vault::open(&path, password).unwrap();
        assert!(vault.list(None).is_empty());
    }

    #[test]
    fn create_rejects_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        Vault::create(&path, password).unwrap();
        let result = Vault::create(&path, password);
        assert!(matches!(result, Err(Error::VaultAlreadyExists(_))));
    }

    #[test]
    fn set_get_remove_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("MY_KEY".into(), "my_value".into(), vec!["aws".into()]);
        vault.save().unwrap();
        drop(vault);

        let mut vault = Vault::open(&path, password).unwrap();
        let entry = vault.get("MY_KEY").unwrap();
        assert_eq!(entry.value.expose_secret(), "my_value");
        assert_eq!(entry.tags, vec!["aws"]);

        vault.remove("MY_KEY").unwrap();
        assert!(vault.get("MY_KEY").is_err());
    }

    #[test]
    fn list_filters_by_tag() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("A".into(), "1".into(), vec!["aws".into()]);
        vault.set("B".into(), "2".into(), vec!["github".into()]);
        vault.set("C".into(), "3".into(), vec!["aws".into(), "prod".into()]);

        let aws = vault.list(Some("aws"));
        assert_eq!(aws.len(), 2);

        let github = vault.list(Some("github"));
        assert_eq!(github.len(), 1);

        let all = vault.list(None);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn tag_and_untag() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("KEY".into(), "val".into(), vec![]);

        vault.tag("KEY", vec!["new-tag".into()]).unwrap();
        assert!(vault.get("KEY").unwrap().has_tag("new-tag"));

        // Adding same tag again is a no-op.
        vault.tag("KEY", vec!["new-tag".into()]).unwrap();
        assert_eq!(vault.get("KEY").unwrap().tags.len(), 1);

        vault.untag("KEY", &["new-tag".into()]).unwrap();
        assert!(!vault.get("KEY").unwrap().has_tag("new-tag"));
    }

    #[test]
    fn remove_many_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("AWS_KEY".into(), "1".into(), vec![]);
        vault.set("AWS_SECRET".into(), "2".into(), vec![]);
        vault.set("GH_TOKEN".into(), "3".into(), vec![]);

        let removed = vault.remove_many(&["AWS_KEY".into(), "AWS_SECRET".into()]);
        assert_eq!(removed.len(), 2);
        assert!(vault.get("AWS_KEY").is_err());
        assert!(vault.get("AWS_SECRET").is_err());
        assert!(vault.get("GH_TOKEN").is_ok());
    }

    #[test]
    fn remove_many_ignores_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("A".into(), "1".into(), vec![]);

        let removed = vault.remove_many(&["A".into(), "NONEXISTENT".into()]);
        assert_eq!(removed.len(), 1);
        assert!(vault.get("A").is_err());
    }

    #[test]
    fn rename_preserves_value_and_tags() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("OLD".into(), "secret".into(), vec!["prod".into()]);

        vault.rename("OLD", "NEW".into()).unwrap();

        assert!(vault.get("OLD").is_err());
        let entry = vault.get("NEW").unwrap();
        assert_eq!(entry.value.expose_secret(), "secret");
        assert_eq!(entry.tags, vec!["prod"]);
        assert_eq!(entry.key, "NEW");
    }

    #[test]
    fn rename_missing_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        let result = vault.rename("NONEXISTENT", "NEW".into());
        assert!(matches!(result, Err(Error::SecretNotFound(_))));
    }

    #[test]
    fn wrong_password_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = test_vault(dir.path());

        Vault::create(&path, b"correct").unwrap();
        let result = Vault::open(&path, b"wrong");
        assert!(result.is_err());
    }
}
