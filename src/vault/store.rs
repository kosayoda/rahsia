use std::fs;

use camino::Utf8Path;

use crate::error::{Error, Result};

/// Magic bytes: "RAHSIA" + format version 1 + padding byte.
const MAGIC: &[u8; 8] = b"RAHSIA\x01\x00";

/// Write an encrypted vault file.
///
/// File format: `MAGIC (8) || salt (16) || encrypted_payload (variable)`.
pub fn write_vault_file(path: &Utf8Path, salt: &[u8; 16], encrypted: &[u8]) -> Result<()> {
    // Write to a temporary file first, then rename for atomicity.
    let tmp_path = path.with_extension("tmp");

    let mut data = Vec::with_capacity(MAGIC.len() + salt.len() + encrypted.len());
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(salt);
    data.extend_from_slice(encrypted);

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&tmp_path, &data)?;
    fs::rename(&tmp_path, path)?;

    Ok(())
}

/// Read an encrypted vault file, returning `(salt, encrypted_payload)`.
pub fn read_vault_file(path: &Utf8Path) -> Result<([u8; 16], Vec<u8>)> {
    if !path.exists() {
        return Err(Error::VaultNotFound(path.to_owned()));
    }

    let data = fs::read(path)?;

    // Validate minimum size: magic (8) + salt (16) + at least some ciphertext.
    if data.len() < MAGIC.len() + 16 {
        return Err(Error::InvalidFormat);
    }

    // Validate magic bytes.
    if &data[..MAGIC.len()] != MAGIC {
        return Err(Error::InvalidFormat);
    }

    let salt: [u8; 16] = data[MAGIC.len()..MAGIC.len() + 16]
        .try_into()
        .map_err(|_| Error::InvalidFormat)?;

    let encrypted = data[MAGIC.len() + 16..].to_vec();

    Ok((salt, encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8Path;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn round_trip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path: &Utf8Path = dir.path().try_into().unwrap();
        let vault_path = path.join("test.vault");
        let salt = [42u8; 16];
        let encrypted = b"some-encrypted-data";

        write_vault_file(&vault_path, &salt, encrypted).unwrap();
        let (read_salt, read_encrypted) = read_vault_file(&vault_path).unwrap();

        assert_eq!(read_salt, salt);
        assert_eq!(read_encrypted, encrypted);
    }

    #[test]
    fn missing_file_returns_not_found() {
        let result = read_vault_file(Utf8Path::new("/nonexistent/vault.enc"));
        assert!(matches!(result, Err(Error::VaultNotFound(_))));
    }

    #[test]
    fn bad_magic_returns_invalid_format() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"NOT_RAHSIA_FORMAT_padding_data_here")
            .unwrap();

        let path: &Utf8Path = file.path().try_into().unwrap();
        let result = read_vault_file(path);
        assert!(matches!(result, Err(Error::InvalidFormat)));
    }

    #[test]
    fn truncated_file_returns_invalid_format() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"RAHSIA\x01\x00").unwrap(); // Magic only, no salt

        let path: &Utf8Path = file.path().try_into().unwrap();
        let result = read_vault_file(path);
        assert!(matches!(result, Err(Error::InvalidFormat)));
    }
}
