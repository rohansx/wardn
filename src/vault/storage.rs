use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::encryption::{self, SensitiveBytes};
use super::placeholder::PlaceholderMap;
use crate::config::{BudgetConfig, OAuthConfig, RateLimitConfig};
use crate::WardenError;

const MAGIC: &[u8; 4] = b"WDNV";
const VERSION: u16 = 1;

/// On-disk representation of a stored credential.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    pub value: String,
    pub allowed_agents: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub budget: Option<BudgetConfig>,
    #[serde(default)]
    pub oauth: Option<OAuthConfig>,
    #[serde(default)]
    pub scrub_patterns: Vec<String>,
    pub created_at: String,
    pub rotated_at: Option<String>,
}

/// Serializable vault data (encrypted payload content).
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultData {
    pub credentials: HashMap<String, StoredCredential>,
    pub placeholders: PlaceholderMap,
}

impl VaultData {
    pub fn empty() -> Self {
        Self {
            credentials: HashMap::new(),
            placeholders: PlaceholderMap::new(),
        }
    }
}

/// File format:
/// ```text
/// Bytes 0-3:   Magic "WDNV"
/// Bytes 4-5:   Version (u16 LE)
/// Bytes 6-21:  Salt (16 bytes)
/// Bytes 22+:   AES-256-GCM encrypted payload (nonce || ciphertext || tag)
/// ```
pub fn save(path: &Path, key: &[u8], salt: &[u8; 16], data: &VaultData) -> crate::Result<()> {
    let json =
        serde_json::to_vec(data).map_err(|e| WardenError::Encryption(format!("serialize: {e}")))?;

    let encrypted = encryption::encrypt(key, &json)?;

    let mut file_data = Vec::with_capacity(4 + 2 + 16 + encrypted.len());
    file_data.extend_from_slice(MAGIC);
    file_data.extend_from_slice(&VERSION.to_le_bytes());
    file_data.extend_from_slice(salt);
    file_data.extend_from_slice(&encrypted);

    // Atomic write: write to .tmp, then rename
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &file_data)?;
    fs::rename(&tmp_path, path)?;

    Ok(())
}

/// Read + validate the file header, returning (file_data, salt).
fn read_and_validate_header(path: &Path) -> crate::Result<(Vec<u8>, [u8; 16])> {
    if !path.exists() {
        return Err(WardenError::VaultNotFound {
            path: path.display().to_string(),
        });
    }

    let file_data = fs::read(path)?;

    if file_data.len() < 22 {
        return Err(WardenError::InvalidFormat("file too short".to_string()));
    }

    if &file_data[0..4] != MAGIC {
        return Err(WardenError::InvalidFormat(
            "invalid magic bytes".to_string(),
        ));
    }

    let version = u16::from_le_bytes([file_data[4], file_data[5]]);
    if version != VERSION {
        return Err(WardenError::InvalidFormat(format!(
            "unsupported version: {version}"
        )));
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&file_data[6..22]);

    Ok((file_data, salt))
}

fn decrypt_payload(key: &[u8], file_data: &[u8]) -> crate::Result<VaultData> {
    let decrypted = encryption::decrypt(key, &file_data[22..])?;
    serde_json::from_slice(&decrypted)
        .map_err(|e| WardenError::Encryption(format!("deserialize: {e}")))
}

/// Load and decrypt a vault file. Returns (data, derived_key, salt).
pub fn load(path: &Path, passphrase: &str) -> crate::Result<(VaultData, SensitiveBytes, [u8; 16])> {
    let (file_data, salt) = read_and_validate_header(path)?;
    let key = encryption::derive_key(passphrase, &salt)?;
    let data = decrypt_payload(key.expose(), &file_data)?;
    Ok((data, key, salt))
}

/// Re-read and decrypt a vault file using an ALREADY-DERIVED key, skipping
/// the (deliberately slow) Argon2id KDF entirely.
///
/// Safe because a vault's salt never changes after `vault create` — the
/// same passphrase always re-derives the same key for a given file, so an
/// already-open `Vault` can cheaply pick up changes another process wrote
/// (e.g. `wardn budget set` while a `wardn serve` daemon is running)
/// without re-authenticating. This is a cache-invalidation mechanism, not
/// an alternate auth path — the key must already have been legitimately
/// derived via `load()` first.
pub fn reload_with_key(path: &Path, key: &[u8]) -> crate::Result<VaultData> {
    let (file_data, _salt) = read_and_validate_header(path)?;
    decrypt_payload(key, &file_data)
}

/// Load with fast key derivation (for tests).
#[cfg(any(test, feature = "test-fast-kdf"))]
pub fn load_fast(
    path: &Path,
    passphrase: &str,
) -> crate::Result<(VaultData, SensitiveBytes, [u8; 16])> {
    if !path.exists() {
        return Err(WardenError::VaultNotFound {
            path: path.display().to_string(),
        });
    }

    let file_data = fs::read(path)?;

    if file_data.len() < 22 {
        return Err(WardenError::InvalidFormat("file too short".to_string()));
    }

    if &file_data[0..4] != MAGIC {
        return Err(WardenError::InvalidFormat(
            "invalid magic bytes".to_string(),
        ));
    }

    let version = u16::from_le_bytes([file_data[4], file_data[5]]);
    if version != VERSION {
        return Err(WardenError::InvalidFormat(format!(
            "unsupported version: {version}"
        )));
    }

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&file_data[6..22]);

    let key = encryption::derive_key_fast(passphrase, &salt)?;

    let decrypted = encryption::decrypt(key.expose(), &file_data[22..])?;

    let data: VaultData = serde_json::from_slice(&decrypted)
        .map_err(|e| WardenError::Encryption(format!("deserialize: {e}")))?;

    Ok((data, key, salt))
}

/// Save with fast key derivation (for tests).
#[cfg(any(test, feature = "test-fast-kdf"))]
pub fn save_with_fast_key(
    path: &Path,
    passphrase: &str,
    data: &VaultData,
) -> crate::Result<(SensitiveBytes, [u8; 16])> {
    let salt = encryption::generate_salt();
    let key = encryption::derive_key_fast(passphrase, &salt)?;
    save(path, key.expose(), &salt, data)?;
    Ok((key, salt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_vault_data() -> VaultData {
        let mut data = VaultData::empty();
        data.credentials.insert(
            "OPENAI_KEY".to_string(),
            StoredCredential {
                value: "sk-proj-test-key-123".to_string(),
                allowed_agents: vec!["researcher".to_string()],
                allowed_domains: vec!["api.openai.com".to_string()],
                rate_limit: None,
                budget: None,
                oauth: None,
                scrub_patterns: Vec::new(),
                created_at: "2026-03-25T00:00:00Z".to_string(),
                rotated_at: None,
            },
        );
        data
    }

    #[test]
    fn test_reload_with_key_sees_changes_written_by_another_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");
        let data = test_vault_data();

        let (key, salt) = save_with_fast_key(&path, "test-pass", &data).unwrap();

        // Simulate another process opening the same vault and writing a
        // change — reload_with_key must see it without re-deriving the key.
        let mut changed = test_vault_data();
        changed.credentials.get_mut("OPENAI_KEY").unwrap().value = "sk-proj-CHANGED".to_string();
        save(&path, key.expose(), &salt, &changed).unwrap();

        let reloaded = reload_with_key(&path, key.expose()).unwrap();
        assert_eq!(reloaded.credentials["OPENAI_KEY"].value, "sk-proj-CHANGED");
    }

    #[test]
    fn test_reload_with_key_wrong_key_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");
        let data = test_vault_data();
        save_with_fast_key(&path, "test-pass", &data).unwrap();

        let wrong_key = vec![0u8; 32];
        assert!(reload_with_key(&path, &wrong_key).is_err());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");
        let data = test_vault_data();

        let (_key, salt) = save_with_fast_key(&path, "test-pass", &data).unwrap();

        let (loaded, _, loaded_salt) = load_fast(&path, "test-pass").unwrap();
        assert_eq!(loaded_salt, salt);
        assert_eq!(loaded.credentials.len(), 1);
        assert_eq!(
            loaded.credentials["OPENAI_KEY"].value,
            "sk-proj-test-key-123"
        );
    }

    #[test]
    fn test_stored_credential_without_budget_field_deserializes() {
        // Vault files written before the budget field existed have no
        // "budget" key at all in their JSON — #[serde(default)] must make
        // this still load cleanly rather than failing to open the vault.
        let json = r#"{
            "value": "sk-proj-old-key",
            "allowed_agents": [],
            "allowed_domains": [],
            "rate_limit": null,
            "created_at": "2026-03-25T00:00:00Z",
            "rotated_at": null
        }"#;
        let cred: StoredCredential = serde_json::from_str(json).unwrap();
        assert!(cred.budget.is_none());
        assert_eq!(cred.value, "sk-proj-old-key");
    }

    #[test]
    fn test_load_wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");
        let data = test_vault_data();

        save_with_fast_key(&path, "correct-pass", &data).unwrap();

        let result = load_fast(&path, "wrong-pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_atomic_write_no_tmp_remains() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");
        let data = test_vault_data();

        save_with_fast_key(&path, "pass", &data).unwrap();

        let tmp_path = path.with_extension("tmp");
        assert!(!tmp_path.exists(), ".tmp file should not remain");
        assert!(path.exists(), "vault file should exist");
    }

    #[test]
    fn test_load_corrupted_file_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");

        // Write valid header but corrupted payload
        let mut file_data = Vec::new();
        file_data.extend_from_slice(MAGIC);
        file_data.extend_from_slice(&VERSION.to_le_bytes());
        file_data.extend_from_slice(&[0u8; 16]); // salt
        file_data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // garbage
        fs::write(&path, &file_data).unwrap();

        let result = load_fast(&path, "any-pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_wrong_magic_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");

        let mut file_data = vec![0u8; 30];
        file_data[0..4].copy_from_slice(b"NOPE");
        fs::write(&path, &file_data).unwrap();

        let result = load_fast(&path, "any-pass");
        assert!(matches!(result, Err(WardenError::InvalidFormat(_))));
    }

    #[test]
    fn test_load_file_too_short_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");

        fs::write(&path, [0u8; 10]).unwrap();

        let result = load_fast(&path, "any-pass");
        assert!(matches!(result, Err(WardenError::InvalidFormat(_))));
    }

    #[test]
    fn test_empty_vault_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");
        let data = VaultData::empty();

        save_with_fast_key(&path, "pass", &data).unwrap();

        let (loaded, _, _) = load_fast(&path, "pass").unwrap();
        assert!(loaded.credentials.is_empty());
    }

    #[test]
    fn test_load_nonexistent_file() {
        let result = load_fast(Path::new("/tmp/nonexistent-vault.enc"), "pass");
        assert!(matches!(result, Err(WardenError::VaultNotFound { .. })));
    }
}
