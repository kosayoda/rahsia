use camino::{Utf8Path, Utf8PathBuf};
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretString};

use crate::error::{Error, Result};
use crate::secret::SecretEntry;

pub struct Vault {
    #[allow(dead_code)]
    path: Utf8PathBuf,
    conn: Connection,
}

impl Vault {
    /// Create a new vault at `path`, encrypted with `password`.
    pub fn create(path: &Utf8Path, password: &[u8]) -> Result<Self> {
        if path.exists() {
            return Err(Error::VaultAlreadyExists(path.to_owned()));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::io(e, format!("failed to create directory {parent}")))?;
        }

        let conn =
            Connection::open(path.as_std_path()).map_err(|e| Error::Database(e.to_string()))?;

        Self::set_key(&conn, password)?;
        Self::init_schema(&conn)?;
        Self::restrict_permissions(path)?;

        Ok(Self {
            path: path.to_owned(),
            conn,
        })
    }

    /// Open an existing vault, decrypting it with `password`.
    pub fn open(path: &Utf8Path, password: &[u8]) -> Result<Self> {
        if !path.exists() {
            return Err(Error::VaultNotFound(path.to_owned()));
        }

        let conn =
            Connection::open(path.as_std_path()).map_err(|e| Error::Database(e.to_string()))?;

        Self::set_key(&conn, password)?;

        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i32>(0)
        })
        .map_err(|_| Error::BadPassword)?;

        Ok(Self {
            path: path.to_owned(),
            conn,
        })
    }

    /// No-op. Mutations are written through to the database immediately.
    pub fn save(&self) -> Result<()> {
        Ok(())
    }

    /// Set a secret. If the (namespace, key) pair already exists, its value and tags are updated.
    pub fn set(
        &mut self,
        ns: &str,
        key: String,
        value: SecretString,
        tags: Vec<String>,
    ) -> Result<()> {
        let now = jiff::Timestamp::now().to_string();
        let tags_json = serde_json::to_string(&tags).map_err(|e| Error::Database(e.to_string()))?;

        self.conn
            .execute(
                "INSERT INTO secrets (namespace, key, value, tags, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(namespace, key) DO UPDATE SET
                   value = excluded.value,
                   tags = excluded.tags,
                   updated_at = excluded.updated_at",
                rusqlite::params![ns, key, value.expose_secret(), tags_json, now],
            )
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(())
    }

    /// Get a secret entry by namespace and key.
    pub fn get(&self, ns: &str, key: &str) -> Result<SecretEntry> {
        self.conn
            .query_row(
                "SELECT namespace, key, value, tags, created_at, updated_at
                 FROM secrets WHERE namespace = ?1 AND key = ?2",
                rusqlite::params![ns, key],
                Self::row_to_entry,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::SecretNotFound(key.to_string()),
                _ => Error::Database(e.to_string()),
            })
    }

    /// Remove a secret by namespace and key.
    pub fn remove(&mut self, ns: &str, key: &str) -> Result<SecretEntry> {
        let entry = self.get(ns, key)?;
        self.conn
            .execute(
                "DELETE FROM secrets WHERE namespace = ?1 AND key = ?2",
                rusqlite::params![ns, key],
            )
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(entry)
    }

    /// Remove multiple secrets by key within a namespace. Returns the removed entries.
    pub fn remove_many(&mut self, ns: &str, keys: &[String]) -> Vec<SecretEntry> {
        keys.iter()
            .filter_map(|k| self.remove(ns, k).ok())
            .collect()
    }

    /// Rename a secret within the same namespace.
    pub fn rename(&mut self, ns: &str, old: &str, new: String) -> Result<()> {
        self.get(ns, old)?;

        let now = jiff::Timestamp::now().to_string();
        let tx = self
            .conn
            .transaction()
            .map_err(|e| Error::Database(e.to_string()))?;

        tx.execute(
            "DELETE FROM secrets WHERE namespace = ?1 AND key = ?2",
            rusqlite::params![ns, &new],
        )
        .map_err(|e| Error::Database(e.to_string()))?;

        tx.execute(
            "UPDATE secrets SET key = ?1, updated_at = ?2
             WHERE namespace = ?3 AND key = ?4",
            rusqlite::params![&new, now, ns, old],
        )
        .map_err(|e| Error::Database(e.to_string()))?;

        tx.commit().map_err(|e| Error::Database(e.to_string()))?;
        Ok(())
    }

    /// Move a secret to a different namespace.
    pub fn move_secret(&mut self, from_ns: &str, key: &str, to_ns: &str) -> Result<()> {
        self.get(from_ns, key)?;

        let now = jiff::Timestamp::now().to_string();
        let tx = self
            .conn
            .transaction()
            .map_err(|e| Error::Database(e.to_string()))?;

        tx.execute(
            "DELETE FROM secrets WHERE namespace = ?1 AND key = ?2",
            rusqlite::params![to_ns, key],
        )
        .map_err(|e| Error::Database(e.to_string()))?;

        tx.execute(
            "UPDATE secrets SET namespace = ?1, updated_at = ?2
             WHERE namespace = ?3 AND key = ?4",
            rusqlite::params![to_ns, now, from_ns, key],
        )
        .map_err(|e| Error::Database(e.to_string()))?;

        tx.commit().map_err(|e| Error::Database(e.to_string()))?;
        Ok(())
    }

    /// List secret entries in a namespace, optionally filtered by tag.
    pub fn list(&self, ns: &str, tag: Option<&str>) -> Vec<SecretEntry> {
        self.list_inner(ns, tag).unwrap_or_default()
    }

    /// List all secret entries across all namespaces, optionally filtered by tag.
    /// Ordered by namespace then key.
    pub fn list_all(&self, tag: Option<&str>) -> Vec<SecretEntry> {
        self.list_all_inner(tag).unwrap_or_default()
    }

    /// Add one or more tags to an existing secret.
    pub fn tag(&mut self, ns: &str, key: &str, tags: Vec<String>) -> Result<()> {
        let mut entry = self.get(ns, key)?;
        let mut changed = false;

        for tag in tags {
            if !entry.tags.contains(&tag) {
                entry.tags.push(tag);
                changed = true;
            }
        }

        if changed {
            let now = jiff::Timestamp::now().to_string();
            let tags_json =
                serde_json::to_string(&entry.tags).map_err(|e| Error::Database(e.to_string()))?;

            self.conn
                .execute(
                    "UPDATE secrets SET tags = ?1, updated_at = ?2
                     WHERE namespace = ?3 AND key = ?4",
                    rusqlite::params![tags_json, now, ns, key],
                )
                .map_err(|e| Error::Database(e.to_string()))?;
        }

        Ok(())
    }

    /// Remove tags from an existing secret.
    pub fn untag(&mut self, ns: &str, key: &str, tags: &[String]) -> Result<()> {
        let mut entry = self.get(ns, key)?;
        let before = entry.tags.len();
        entry.tags.retain(|t| !tags.contains(t));

        if entry.tags.len() != before {
            let now = jiff::Timestamp::now().to_string();
            let tags_json =
                serde_json::to_string(&entry.tags).map_err(|e| Error::Database(e.to_string()))?;

            self.conn
                .execute(
                    "UPDATE secrets SET tags = ?1, updated_at = ?2
                     WHERE namespace = ?3 AND key = ?4",
                    rusqlite::params![tags_json, now, ns, key],
                )
                .map_err(|e| Error::Database(e.to_string()))?;
        }

        Ok(())
    }

    /// Get all unique tags across all entries in a namespace.
    pub fn tags(&self, ns: &str) -> Vec<String> {
        self.tags_inner(ns).unwrap_or_default()
    }

    /// Get all unique namespace names (excluding the default empty namespace).
    pub fn namespaces(&self) -> Vec<String> {
        self.namespaces_inner().unwrap_or_default()
    }

    /// Re-encrypt the vault with a new password.
    pub fn change_password(&mut self, new_password: &[u8]) -> Result<()> {
        let escaped = Self::escape_password(new_password);
        self.conn
            .execute_batch(&format!("PRAGMA rekey = '{escaped}'"))
            .map_err(|e| Error::Database(e.to_string()))
    }

    // --- Private helpers ---

    fn set_key(conn: &Connection, password: &[u8]) -> Result<()> {
        let escaped = Self::escape_password(password);
        conn.execute_batch(&format!("PRAGMA key = '{escaped}'"))
            .map_err(|e| Error::Database(e.to_string()))
    }

    fn escape_password(password: &[u8]) -> String {
        String::from_utf8_lossy(password).replace('\'', "''")
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS secrets (
                namespace  TEXT NOT NULL DEFAULT '',
                key        TEXT NOT NULL,
                value      TEXT NOT NULL,
                tags       TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            );",
        )
        .map_err(|e| Error::Database(e.to_string()))
    }

    fn restrict_permissions(_path: &Utf8Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(_path.as_std_path(), std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::io(e, format!("failed to set permissions on {_path}")))?;
        }
        Ok(())
    }

    fn list_inner(&self, ns: &str, tag: Option<&str>) -> Result<Vec<SecretEntry>> {
        match tag {
            Some(t) => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT namespace, key, value, tags, created_at, updated_at
                         FROM secrets
                         WHERE namespace = ?1
                           AND EXISTS (SELECT 1 FROM json_each(tags) WHERE value = ?2)
                         ORDER BY key",
                    )
                    .map_err(|e| Error::Database(e.to_string()))?;

                let rows = stmt
                    .query_map(rusqlite::params![ns, t], Self::row_to_entry)
                    .map_err(|e| Error::Database(e.to_string()))?;

                Ok(rows.filter_map(|r| r.ok()).collect())
            }
            None => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT namespace, key, value, tags, created_at, updated_at
                         FROM secrets
                         WHERE namespace = ?1
                         ORDER BY key",
                    )
                    .map_err(|e| Error::Database(e.to_string()))?;

                let rows = stmt
                    .query_map(rusqlite::params![ns], Self::row_to_entry)
                    .map_err(|e| Error::Database(e.to_string()))?;

                Ok(rows.filter_map(|r| r.ok()).collect())
            }
        }
    }

    fn list_all_inner(&self, tag: Option<&str>) -> Result<Vec<SecretEntry>> {
        match tag {
            Some(t) => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT namespace, key, value, tags, created_at, updated_at
                         FROM secrets
                         WHERE EXISTS (SELECT 1 FROM json_each(tags) WHERE value = ?1)
                         ORDER BY namespace, key",
                    )
                    .map_err(|e| Error::Database(e.to_string()))?;

                let rows = stmt
                    .query_map(rusqlite::params![t], Self::row_to_entry)
                    .map_err(|e| Error::Database(e.to_string()))?;

                Ok(rows.filter_map(|r| r.ok()).collect())
            }
            None => {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT namespace, key, value, tags, created_at, updated_at
                         FROM secrets
                         ORDER BY namespace, key",
                    )
                    .map_err(|e| Error::Database(e.to_string()))?;

                let rows = stmt
                    .query_map([], Self::row_to_entry)
                    .map_err(|e| Error::Database(e.to_string()))?;

                Ok(rows.filter_map(|r| r.ok()).collect())
            }
        }
    }

    fn tags_inner(&self, ns: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT j.value
                 FROM secrets, json_each(secrets.tags) AS j
                 WHERE secrets.namespace = ?1
                 ORDER BY j.value",
            )
            .map_err(|e| Error::Database(e.to_string()))?;

        let rows = stmt
            .query_map(rusqlite::params![ns], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    fn namespaces_inner(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT namespace FROM secrets
                 WHERE namespace != ''
                 ORDER BY namespace",
            )
            .map_err(|e| Error::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Database(e.to_string()))?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretEntry> {
        let namespace: String = row.get(0)?;
        let key: String = row.get(1)?;
        let value_str: String = row.get(2)?;
        let tags_json: String = row.get(3)?;
        let created_at_str: String = row.get(4)?;
        let updated_at_str: String = row.get(5)?;

        let value = SecretString::from(value_str);
        let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
        let created_at: jiff::Timestamp = created_at_str
            .parse()
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
        let updated_at: jiff::Timestamp = updated_at_str
            .parse()
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH);

        Ok(SecretEntry {
            namespace,
            key,
            value,
            tags,
            created_at,
            updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn test_vault(dir: &std::path::Path) -> (Utf8PathBuf, &[u8]) {
        let dir: &Utf8Path = dir.try_into().unwrap();
        let path = dir.join("test.db");
        let password = b"test-password";
        (path, password)
    }

    #[test]
    fn create_and_reopen_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let vault = Vault::create(&path, password).unwrap();
        assert!(vault.list("", None).is_empty());
        drop(vault);

        let vault = Vault::open(&path, password).unwrap();
        assert!(vault.list("", None).is_empty());
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
        vault
            .set("", "MY_KEY".into(), "my_value".into(), vec!["aws".into()])
            .unwrap();
        drop(vault);

        let mut vault = Vault::open(&path, password).unwrap();
        let entry = vault.get("", "MY_KEY").unwrap();
        assert_eq!(entry.value.expose_secret(), "my_value");
        assert_eq!(entry.tags, vec!["aws"]);

        vault.remove("", "MY_KEY").unwrap();
        assert!(vault.get("", "MY_KEY").is_err());
    }

    #[test]
    fn list_filters_by_tag() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault
            .set("", "A".into(), "1".into(), vec!["aws".into()])
            .unwrap();
        vault
            .set("", "B".into(), "2".into(), vec!["github".into()])
            .unwrap();
        vault
            .set(
                "",
                "C".into(),
                "3".into(),
                vec!["aws".into(), "prod".into()],
            )
            .unwrap();

        assert_eq!(vault.list("", Some("aws")).len(), 2);
        assert_eq!(vault.list("", Some("github")).len(), 1);
        assert_eq!(vault.list("", None).len(), 3);
    }

    #[test]
    fn tag_and_untag() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("", "KEY".into(), "val".into(), vec![]).unwrap();

        vault.tag("", "KEY", vec!["new-tag".into()]).unwrap();
        assert!(vault.get("", "KEY").unwrap().has_tag("new-tag"));

        vault.tag("", "KEY", vec!["new-tag".into()]).unwrap();
        assert_eq!(vault.get("", "KEY").unwrap().tags.len(), 1);

        vault.untag("", "KEY", &["new-tag".into()]).unwrap();
        assert!(!vault.get("", "KEY").unwrap().has_tag("new-tag"));
    }

    #[test]
    fn remove_many_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("", "AWS_KEY".into(), "1".into(), vec![]).unwrap();
        vault
            .set("", "AWS_SECRET".into(), "2".into(), vec![])
            .unwrap();
        vault
            .set("", "GH_TOKEN".into(), "3".into(), vec![])
            .unwrap();

        let removed = vault.remove_many("", &["AWS_KEY".into(), "AWS_SECRET".into()]);
        assert_eq!(removed.len(), 2);
        assert!(vault.get("", "AWS_KEY").is_err());
        assert!(vault.get("", "AWS_SECRET").is_err());
        assert!(vault.get("", "GH_TOKEN").is_ok());
    }

    #[test]
    fn remove_many_ignores_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("", "A".into(), "1".into(), vec![]).unwrap();

        let removed = vault.remove_many("", &["A".into(), "NONEXISTENT".into()]);
        assert_eq!(removed.len(), 1);
        assert!(vault.get("", "A").is_err());
    }

    #[test]
    fn rename_preserves_value_and_tags() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault
            .set("", "OLD".into(), "secret".into(), vec!["prod".into()])
            .unwrap();

        vault.rename("", "OLD", "NEW".into()).unwrap();

        assert!(vault.get("", "OLD").is_err());
        let entry = vault.get("", "NEW").unwrap();
        assert_eq!(entry.value.expose_secret(), "secret");
        assert_eq!(entry.tags, vec!["prod"]);
        assert_eq!(entry.key, "NEW");
    }

    #[test]
    fn rename_missing_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        let result = vault.rename("", "NONEXISTENT", "NEW".into());
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

    #[test]
    fn persistence_without_explicit_save() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("", "KEY".into(), "val".into(), vec![]).unwrap();
        drop(vault);

        let vault = Vault::open(&path, password).unwrap();
        assert_eq!(vault.get("", "KEY").unwrap().value.expose_secret(), "val");
    }

    #[test]
    fn change_password_allows_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("", "KEY".into(), "val".into(), vec![]).unwrap();
        vault.change_password(b"new-password").unwrap();
        drop(vault);

        assert!(Vault::open(&path, b"test-password").is_err());
        let vault = Vault::open(&path, b"new-password").unwrap();
        assert_eq!(vault.get("", "KEY").unwrap().value.expose_secret(), "val");
    }

    #[test]
    fn same_key_different_namespaces() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault
            .set(
                "timecard",
                "DATABASE_URL".into(),
                "postgres://tc".into(),
                vec![],
            )
            .unwrap();
        vault
            .set(
                "warehouse",
                "DATABASE_URL".into(),
                "postgres://wh".into(),
                vec![],
            )
            .unwrap();
        vault
            .set("", "API_KEY".into(), "global-key".into(), vec![])
            .unwrap();

        let tc = vault.get("timecard", "DATABASE_URL").unwrap();
        assert_eq!(tc.value.expose_secret(), "postgres://tc");

        let wh = vault.get("warehouse", "DATABASE_URL").unwrap();
        assert_eq!(wh.value.expose_secret(), "postgres://wh");

        assert!(vault.get("", "DATABASE_URL").is_err());

        assert_eq!(vault.list("timecard", None).len(), 1);
        assert_eq!(vault.list("warehouse", None).len(), 1);
        assert_eq!(vault.list("", None).len(), 1);
        assert_eq!(vault.list_all(None).len(), 3);
    }

    #[test]
    fn namespaces_returns_unique_names() {
        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        let mut vault = Vault::create(&path, password).unwrap();
        vault.set("alpha", "A".into(), "1".into(), vec![]).unwrap();
        vault.set("beta", "B".into(), "2".into(), vec![]).unwrap();
        vault.set("alpha", "C".into(), "3".into(), vec![]).unwrap();
        vault.set("", "D".into(), "4".into(), vec![]).unwrap();

        let ns = vault.namespaces();
        assert_eq!(ns, vec!["alpha", "beta"]);
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_has_restricted_permissions() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let (path, password) = test_vault(dir.path());

        Vault::create(&path, password).unwrap();

        let mode = std::fs::metadata(path.as_std_path()).unwrap().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "vault file should be owner-only (0600)"
        );
    }
}
