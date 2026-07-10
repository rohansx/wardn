pub mod encryption;
pub mod keyring_store;
pub mod placeholder;
pub mod storage;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;

use encryption::{SensitiveBytes, SensitiveString};
use placeholder::{PlaceholderMap, PlaceholderToken};
use storage::{StoredCredential, VaultData};

use crate::config::CredentialConfig;
use crate::WardenError;

/// Info about a credential (no secret values).
#[derive(Debug, Clone)]
pub struct CredentialInfo {
    pub name: String,
    pub allowed_agents: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub has_rate_limit: bool,
    pub created_at: String,
    pub rotated_at: Option<String>,
}

/// The core vault: stores encrypted credentials and issues placeholder tokens.
pub struct Vault {
    credentials: HashMap<String, CredentialEntry>,
    placeholders: PlaceholderMap,
    key: SensitiveBytes,
    salt: [u8; 16],
    path: Option<PathBuf>,
}

struct CredentialEntry {
    value: SensitiveString,
    allowed_agents: Vec<String>,
    allowed_domains: Vec<String>,
    rate_limit: Option<crate::config::RateLimitConfig>,
    budget: Option<crate::config::BudgetConfig>,
    oauth: Option<crate::config::OAuthConfig>,
    scrub_patterns: Vec<String>,
    created_at: String,
    rotated_at: Option<String>,
}

fn stored_to_entries(
    stored: HashMap<String, StoredCredential>,
) -> HashMap<String, CredentialEntry> {
    stored
        .into_iter()
        .map(|(name, stored)| {
            let entry = CredentialEntry {
                value: SensitiveString::new(stored.value),
                allowed_agents: stored.allowed_agents,
                allowed_domains: stored.allowed_domains,
                rate_limit: stored.rate_limit,
                budget: stored.budget,
                oauth: stored.oauth,
                scrub_patterns: stored.scrub_patterns,
                created_at: stored.created_at,
                rotated_at: stored.rotated_at,
            };
            (name, entry)
        })
        .collect()
}

impl Vault {
    /// Create a new vault file with a passphrase.
    pub fn create(path: &Path, passphrase: &str) -> crate::Result<Self> {
        let salt = encryption::generate_salt();
        let key = encryption::derive_key(passphrase, &salt)?;

        let vault = Self {
            credentials: HashMap::new(),
            placeholders: PlaceholderMap::new(),
            key,
            salt,
            path: Some(path.to_path_buf()),
        };

        vault.save()?;
        Ok(vault)
    }

    /// Open an existing vault file.
    pub fn open(path: &Path, passphrase: &str) -> crate::Result<Self> {
        let (data, key, salt) = storage::load(path, passphrase)?;
        Self::from_vault_data(data, key, salt, Some(path.to_path_buf()))
    }

    fn from_vault_data(
        mut data: VaultData,
        key: SensitiveBytes,
        salt: [u8; 16],
        path: Option<PathBuf>,
    ) -> crate::Result<Self> {
        data.placeholders.rebuild_reverse();
        let credentials = stored_to_entries(data.credentials);

        Ok(Self {
            credentials,
            placeholders: data.placeholders,
            key,
            salt,
            path,
        })
    }

    /// Re-read this vault's file from disk, replacing in-memory credentials
    /// and placeholders. A no-op for ephemeral (in-memory-only) vaults.
    ///
    /// Cheap — reuses the already-derived key (see
    /// `storage::reload_with_key`), so no Argon2id KDF cost. This is what
    /// lets a CLI process's `wardn budget set` (or `vault set`, `vault
    /// rotate`, etc.) become visible to an already-running `wardn serve`
    /// daemon without restarting it — the two are separate OS processes
    /// with independent memory, so the daemon otherwise never sees a
    /// change another process wrote to the vault file.
    pub fn reload(&mut self) -> crate::Result<()> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };

        let mut data = storage::reload_with_key(&path, self.key.expose())?;
        data.placeholders.rebuild_reverse();
        self.credentials = stored_to_entries(data.credentials);
        self.placeholders = data.placeholders;
        Ok(())
    }

    /// Create an ephemeral in-memory vault (for testing).
    pub fn ephemeral() -> Self {
        Self {
            credentials: HashMap::new(),
            placeholders: PlaceholderMap::new(),
            key: SensitiveBytes::new(vec![0u8; 32]),
            salt: [0u8; 16],
            path: None,
        }
    }

    /// Store a credential. Overwrites if it already exists.
    pub fn set(&mut self, name: &str, value: &str) -> crate::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.credentials.insert(
            name.to_string(),
            CredentialEntry {
                value: SensitiveString::new(value),
                allowed_agents: Vec::new(),
                allowed_domains: Vec::new(),
                rate_limit: None,
                budget: None,
                oauth: None,
                scrub_patterns: Vec::new(),
                created_at: now,
                rotated_at: None,
            },
        );
        self.save()
    }

    /// Store a credential with full configuration.
    pub fn set_with_config(
        &mut self,
        name: &str,
        value: &str,
        config: &CredentialConfig,
    ) -> crate::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.credentials.insert(
            name.to_string(),
            CredentialEntry {
                value: SensitiveString::new(value),
                allowed_agents: config.allowed_agents.clone(),
                allowed_domains: config.allowed_domains.clone(),
                rate_limit: config.rate_limit.clone(),
                budget: config.budget,
                oauth: config.oauth.clone(),
                scrub_patterns: config.scrub_patterns.clone(),
                created_at: now,
                rotated_at: None,
            },
        );
        self.save()
    }

    /// Get a credential value (internal only — never exposed via MCP).
    pub fn get(&self, name: &str) -> Option<&SensitiveString> {
        self.credentials.get(name).map(|e| &e.value)
    }

    /// Path this vault was opened from, or None for an ephemeral (in-memory
    /// only) vault. Useful for surfacing the active vault in dashboard UIs
    /// without re-asking the caller for the path.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// List all credentials (names + metadata, no values).
    pub fn list(&self) -> Vec<CredentialInfo> {
        self.credentials
            .iter()
            .map(|(name, entry)| CredentialInfo {
                name: name.clone(),
                allowed_agents: entry.allowed_agents.clone(),
                allowed_domains: entry.allowed_domains.clone(),
                has_rate_limit: entry.rate_limit.is_some(),
                created_at: entry.created_at.clone(),
                rotated_at: entry.rotated_at.clone(),
            })
            .collect()
    }

    /// Names of credentials that have an OAuth config, i.e. are backed by
    /// a refreshable access token rather than a static key.
    pub fn oauth_credential_names(&self) -> Vec<String> {
        self.credentials
            .iter()
            .filter(|(_, entry)| entry.oauth.is_some())
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Rotate a credential value. Placeholders remain unchanged.
    pub fn rotate(&mut self, name: &str, new_value: &str) -> crate::Result<()> {
        let entry =
            self.credentials
                .get_mut(name)
                .ok_or_else(|| WardenError::CredentialNotFound {
                    name: name.to_string(),
                })?;

        entry.value = SensitiveString::new(new_value);
        entry.rotated_at = Some(Utc::now().to_rfc3339());
        self.save()
    }

    /// Remove a credential and all its placeholders.
    pub fn remove(&mut self, name: &str) -> crate::Result<()> {
        if self.credentials.remove(name).is_none() {
            return Err(WardenError::CredentialNotFound {
                name: name.to_string(),
            });
        }
        self.placeholders.remove_credential(name);
        self.save()
    }

    /// Get or create a placeholder token for an agent.
    /// Checks that the agent is authorized for this credential.
    pub fn get_placeholder(
        &mut self,
        credential_name: &str,
        agent_id: &str,
    ) -> crate::Result<PlaceholderToken> {
        let entry = self.credentials.get(credential_name).ok_or_else(|| {
            WardenError::CredentialNotFound {
                name: credential_name.to_string(),
            }
        })?;

        // If allowed_agents is empty, all agents are authorized
        if !entry.allowed_agents.is_empty() && !entry.allowed_agents.contains(&agent_id.to_string())
        {
            return Err(WardenError::Unauthorized {
                agent_id: agent_id.to_string(),
                credential: credential_name.to_string(),
            });
        }

        let token = self.placeholders.get_or_create(credential_name, agent_id);
        self.save()?;
        Ok(token)
    }

    /// Resolve a placeholder to its credential name and decrypted value.
    pub fn resolve_placeholder(&self, placeholder: &str) -> Option<(&str, &SensitiveString)> {
        let (cred_name, _agent_id) = self.placeholders.resolve(placeholder)?;
        let entry = self.credentials.get(cred_name)?;
        Some((cred_name, &entry.value))
    }

    /// Resolve a placeholder ONLY if it was actually issued to
    /// `claimed_agent_id`.
    ///
    /// The proxy identifies the caller via the `x-warden-agent` header,
    /// which is just an unauthenticated claim any local process can set to
    /// anything. Without this check, a placeholder stolen from agent A
    /// still resolves to the real credential when presented under a
    /// different claimed agent name — meaning per-agent rate limits and
    /// budgets get attributed to whatever the thief claims, not to A, and
    /// per-agent revocation can't actually stop a leaked token. Binding
    /// resolution to the placeholder's true owner closes that: a mismatched
    /// claim is treated exactly like an unknown token (no injection, no
    /// error — same as any other unrecognized placeholder).
    pub fn resolve_placeholder_for_agent(
        &self,
        placeholder: &str,
        claimed_agent_id: &str,
    ) -> Option<(&str, &SensitiveString)> {
        let (cred_name, actual_agent_id) = self.placeholders.resolve(placeholder)?;
        if actual_agent_id != claimed_agent_id {
            return None;
        }
        let entry = self.credentials.get(cred_name)?;
        Some((cred_name, &entry.value))
    }

    /// Get the placeholder string for a (credential, agent) pair without creating one.
    pub fn placeholder_for(&self, credential_name: &str, agent_id: &str) -> Option<String> {
        self.placeholders
            .lookup(credential_name, agent_id)
            .map(|s| s.to_string())
    }

    /// Check if an agent is authorized for a credential.
    pub fn is_agent_authorized(&self, credential_name: &str, agent_id: &str) -> bool {
        match self.credentials.get(credential_name) {
            Some(entry) => {
                entry.allowed_agents.is_empty()
                    || entry.allowed_agents.contains(&agent_id.to_string())
            }
            None => false,
        }
    }

    /// Check if a domain is allowed for a credential.
    pub fn is_domain_allowed(&self, credential_name: &str, domain: &str) -> bool {
        match self.credentials.get(credential_name) {
            Some(entry) => {
                entry.allowed_domains.is_empty()
                    || entry.allowed_domains.contains(&domain.to_string())
            }
            None => false,
        }
    }

    /// Get the rate limit config for a credential.
    pub fn rate_limit_config(
        &self,
        credential_name: &str,
    ) -> Option<&crate::config::RateLimitConfig> {
        self.credentials
            .get(credential_name)
            .and_then(|e| e.rate_limit.as_ref())
    }

    /// Get the budget config for a credential, if any (`wardn budget set`).
    /// Read live on every proxy request — see `proxy::budget`.
    pub fn budget_config(&self, credential_name: &str) -> Option<&crate::config::BudgetConfig> {
        self.credentials
            .get(credential_name)
            .and_then(|e| e.budget.as_ref())
    }

    /// Set (or clear, with `None`) the budget for an existing credential.
    pub fn set_budget(
        &mut self,
        credential_name: &str,
        budget: Option<crate::config::BudgetConfig>,
    ) -> crate::Result<()> {
        let entry = self.credentials.get_mut(credential_name).ok_or_else(|| {
            WardenError::CredentialNotFound {
                name: credential_name.to_string(),
            }
        })?;
        entry.budget = budget;
        self.save()
    }

    /// Set (or clear, with an empty vec) the allowed domains for an
    /// existing credential. An empty list means "any domain" — see
    /// `is_domain_allowed`.
    pub fn set_allowed_domains(
        &mut self,
        credential_name: &str,
        domains: Vec<String>,
    ) -> crate::Result<()> {
        let entry = self.credentials.get_mut(credential_name).ok_or_else(|| {
            WardenError::CredentialNotFound {
                name: credential_name.to_string(),
            }
        })?;
        entry.allowed_domains = domains;
        self.save()
    }

    /// Get the OAuth config for a credential, if it's OAuth-backed.
    pub fn oauth_config(&self, credential_name: &str) -> Option<&crate::config::OAuthConfig> {
        self.credentials
            .get(credential_name)
            .and_then(|e| e.oauth.as_ref())
    }

    /// Regex patterns configured to redact derived secrets from responses
    /// on requests that inject this credential. Empty if none configured.
    pub fn scrub_patterns(&self, credential_name: &str) -> &[String] {
        self.credentials
            .get(credential_name)
            .map(|e| e.scrub_patterns.as_slice())
            .unwrap_or(&[])
    }

    /// Set (or clear, with `None`) the OAuth config for an existing
    /// credential. Setting it doesn't change the credential's current
    /// `value` — that's updated separately by `update_oauth_tokens` once a
    /// refresh actually happens.
    pub fn set_oauth_config(
        &mut self,
        credential_name: &str,
        oauth: Option<crate::config::OAuthConfig>,
    ) -> crate::Result<()> {
        let entry = self.credentials.get_mut(credential_name).ok_or_else(|| {
            WardenError::CredentialNotFound {
                name: credential_name.to_string(),
            }
        })?;
        entry.oauth = oauth;
        self.save()
    }

    /// After a successful OAuth refresh: store the new access token as the
    /// credential's value (this is what actually gets injected into
    /// requests), and update the refresh token / expiry for next time.
    /// `new_refresh_token` is `None` when the provider didn't rotate it.
    pub fn update_oauth_tokens(
        &mut self,
        credential_name: &str,
        new_access_token: &str,
        new_refresh_token: Option<&str>,
        new_expires_at: Option<i64>,
    ) -> crate::Result<()> {
        let entry = self.credentials.get_mut(credential_name).ok_or_else(|| {
            WardenError::CredentialNotFound {
                name: credential_name.to_string(),
            }
        })?;
        entry.value = SensitiveString::new(new_access_token);
        if let Some(oauth) = entry.oauth.as_mut() {
            if let Some(rt) = new_refresh_token {
                oauth.refresh_token = rt.to_string();
            }
            oauth.expires_at = new_expires_at;
        }
        self.save()
    }

    /// Persist vault to disk.
    pub fn save(&self) -> crate::Result<()> {
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()), // ephemeral vault, no-op
        };

        let data = self.to_vault_data();
        storage::save(path, self.key.expose(), &self.salt, &data)
    }

    /// Number of stored credentials.
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    fn to_vault_data(&self) -> VaultData {
        let credentials = self
            .credentials
            .iter()
            .map(|(name, entry)| {
                let stored = StoredCredential {
                    value: entry.value.expose().to_string(),
                    allowed_agents: entry.allowed_agents.clone(),
                    allowed_domains: entry.allowed_domains.clone(),
                    rate_limit: entry.rate_limit.clone(),
                    budget: entry.budget,
                    oauth: entry.oauth.clone(),
                    scrub_patterns: entry.scrub_patterns.clone(),
                    created_at: entry.created_at.clone(),
                    rotated_at: entry.rotated_at.clone(),
                };
                (name.clone(), stored)
            })
            .collect();

        VaultData {
            credentials,
            placeholders: self.placeholders.clone(),
        }
    }
}

/// Test-only factory methods using fast key derivation.
#[cfg(any(test, feature = "test-fast-kdf"))]
impl Vault {
    pub fn create_fast(path: &Path, passphrase: &str) -> crate::Result<Self> {
        let salt = encryption::generate_salt();
        let key = encryption::derive_key_fast(passphrase, &salt)?;

        let vault = Self {
            credentials: HashMap::new(),
            placeholders: PlaceholderMap::new(),
            key,
            salt,
            path: Some(path.to_path_buf()),
        };

        vault.save()?;
        Ok(vault)
    }

    pub fn open_fast(path: &Path, passphrase: &str) -> crate::Result<Self> {
        let (data, key, salt) = storage::load_fast(path, passphrase)?;
        Self::from_vault_data(data, key, salt, Some(path.to_path_buf()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BudgetConfig, BudgetMode, BudgetWindow, CredentialConfig, OAuthConfig, RateLimitConfig,
        TimePeriod,
    };
    use tempfile::TempDir;

    #[test]
    fn test_create_and_open_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");

        {
            let mut vault = Vault::create_fast(&path, "my-pass").unwrap();
            vault.set("OPENAI_KEY", "sk-test-123").unwrap();
            vault.set("ANTHROPIC_KEY", "sk-ant-456").unwrap();
        }

        let vault = Vault::open_fast(&path, "my-pass").unwrap();
        assert_eq!(vault.len(), 2);
        assert_eq!(vault.get("OPENAI_KEY").unwrap().expose(), "sk-test-123");
        assert_eq!(vault.get("ANTHROPIC_KEY").unwrap().expose(), "sk-ant-456");
    }

    #[test]
    fn test_reload_picks_up_changes_from_another_process() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.enc");

        // "process A" — creates the vault and keeps its handle open, like a
        // long-running `wardn serve` daemon would.
        let mut daemon_vault = Vault::create_fast(&path, "my-pass").unwrap();
        daemon_vault.set("OPENAI_KEY", "sk-original").unwrap();
        assert!(daemon_vault.budget_config("OPENAI_KEY").is_none());

        // "process B" — a separate `wardn budget set` CLI invocation opens
        // its own handle to the SAME file and writes a change.
        {
            let mut cli_vault = Vault::open_fast(&path, "my-pass").unwrap();
            cli_vault
                .set_budget(
                    "OPENAI_KEY",
                    Some(BudgetConfig {
                        max_usd: 7.0,
                        window: BudgetWindow::Day,
                        mode: BudgetMode::Hard,
                    }),
                )
                .unwrap();
        }

        // Without reload, process A's in-memory copy is stale.
        assert!(daemon_vault.budget_config("OPENAI_KEY").is_none());

        // reload() picks up the change without needing the passphrase again.
        daemon_vault.reload().unwrap();
        let budget = daemon_vault.budget_config("OPENAI_KEY").unwrap();
        assert_eq!(budget.max_usd, 7.0);
    }

    #[test]
    fn test_reload_is_noop_for_ephemeral_vault() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();
        vault.reload().unwrap(); // must not error or clear data
        assert_eq!(vault.get("KEY").unwrap().expose(), "secret");
    }

    #[test]
    fn test_budget_config_absent_by_default() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();
        assert!(vault.budget_config("KEY").is_none());
    }

    #[test]
    fn test_set_with_config_stores_budget() {
        let mut vault = Vault::ephemeral();
        let budget = BudgetConfig {
            max_usd: 5.0,
            window: BudgetWindow::Day,
            mode: BudgetMode::Hard,
        };
        vault
            .set_with_config(
                "KEY",
                "secret",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    allowed_agents: vec![],
                    allowed_domains: vec![],
                    rate_limit: None,
                    budget: Some(budget),
                },
            )
            .unwrap();

        let stored = vault.budget_config("KEY").unwrap();
        assert_eq!(stored.max_usd, 5.0);
    }

    #[test]
    fn test_scrub_patterns_empty_by_default() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();
        assert!(vault.scrub_patterns("KEY").is_empty());
        assert!(vault.scrub_patterns("NONEXISTENT").is_empty());
    }

    #[test]
    fn test_set_with_config_stores_scrub_patterns() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "secret",
                &CredentialConfig {
                    scrub_patterns: vec![r"sess_[a-zA-Z0-9]{16,}".to_string()],
                    oauth: None,
                    allowed_agents: vec![],
                    allowed_domains: vec![],
                    rate_limit: None,
                    budget: None,
                },
            )
            .unwrap();

        assert_eq!(
            vault.scrub_patterns("KEY"),
            vec![r"sess_[a-zA-Z0-9]{16,}".to_string()]
        );
    }

    #[test]
    fn test_set_budget_on_existing_credential() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();
        assert!(vault.budget_config("KEY").is_none());

        vault
            .set_budget(
                "KEY",
                Some(BudgetConfig {
                    max_usd: 2.5,
                    window: BudgetWindow::Total,
                    mode: BudgetMode::Soft,
                }),
            )
            .unwrap();

        let budget = vault.budget_config("KEY").unwrap();
        assert_eq!(budget.max_usd, 2.5);
        assert_eq!(budget.mode, BudgetMode::Soft);
    }

    #[test]
    fn test_set_budget_can_clear_it() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();
        vault
            .set_budget(
                "KEY",
                Some(BudgetConfig {
                    max_usd: 2.5,
                    window: BudgetWindow::Day,
                    mode: BudgetMode::Hard,
                }),
            )
            .unwrap();
        vault.set_budget("KEY", None).unwrap();
        assert!(vault.budget_config("KEY").is_none());
    }

    #[test]
    fn test_set_budget_on_nonexistent_credential_fails() {
        let mut vault = Vault::ephemeral();
        let result = vault.set_budget(
            "NOPE",
            Some(BudgetConfig {
                max_usd: 1.0,
                window: BudgetWindow::Day,
                mode: BudgetMode::Hard,
            }),
        );
        assert!(matches!(
            result,
            Err(WardenError::CredentialNotFound { .. })
        ));
    }

    #[test]
    fn test_set_allowed_domains_scopes_credential() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();
        assert!(vault.is_domain_allowed("KEY", "anything.com")); // open by default

        vault
            .set_allowed_domains("KEY", vec!["api.example.com".to_string()])
            .unwrap();

        assert!(vault.is_domain_allowed("KEY", "api.example.com"));
        assert!(!vault.is_domain_allowed("KEY", "evil.com"));
    }

    #[test]
    fn test_set_and_get() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "value-123").unwrap();
        assert_eq!(vault.get("KEY").unwrap().expose(), "value-123");
    }

    #[test]
    fn test_set_overwrites() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "old-value").unwrap();
        vault.set("KEY", "new-value").unwrap();
        assert_eq!(vault.get("KEY").unwrap().expose(), "new-value");
    }

    #[test]
    fn test_get_nonexistent_returns_none() {
        let vault = Vault::ephemeral();
        assert!(vault.get("NOPE").is_none());
    }

    #[test]
    fn test_list_returns_names_not_values() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY_A", "secret-a").unwrap();
        vault.set("KEY_B", "secret-b").unwrap();

        let list = vault.list();
        assert_eq!(list.len(), 2);

        let names: Vec<&str> = list.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"KEY_A"));
        assert!(names.contains(&"KEY_B"));

        // CredentialInfo has no value field — this is a compile-time guarantee
    }

    #[test]
    fn test_oauth_credential_names_only_lists_oauth_backed_credentials() {
        let mut vault = Vault::ephemeral();
        vault.set("STATIC_KEY", "sk-static").unwrap();
        vault
            .set_oauth_config(
                "STATIC_KEY",
                None, // no-op, but exercises the API for a credential with no oauth
            )
            .unwrap();

        vault.set("OAUTH_KEY", "initial-access-token").unwrap();
        vault
            .set_oauth_config(
                "OAUTH_KEY",
                Some(OAuthConfig {
                    token_url: "https://example.com/token".to_string(),
                    client_id: "id".to_string(),
                    client_secret: None,
                    refresh_token: "rt".to_string(),
                    expires_at: None,
                }),
            )
            .unwrap();

        let names = vault.oauth_credential_names();
        assert_eq!(names, vec!["OAUTH_KEY".to_string()]);
    }

    #[test]
    fn test_update_oauth_tokens_updates_value_and_refresh_state() {
        let mut vault = Vault::ephemeral();
        vault.set("OAUTH_KEY", "old-access-token").unwrap();
        vault
            .set_oauth_config(
                "OAUTH_KEY",
                Some(OAuthConfig {
                    token_url: "https://example.com/token".to_string(),
                    client_id: "id".to_string(),
                    client_secret: None,
                    refresh_token: "old-refresh".to_string(),
                    expires_at: Some(100),
                }),
            )
            .unwrap();

        vault
            .update_oauth_tokens(
                "OAUTH_KEY",
                "new-access-token",
                Some("new-refresh"),
                Some(9999),
            )
            .unwrap();

        assert_eq!(vault.get("OAUTH_KEY").unwrap().expose(), "new-access-token");
        let oauth = vault.oauth_config("OAUTH_KEY").unwrap();
        assert_eq!(oauth.refresh_token, "new-refresh");
        assert_eq!(oauth.expires_at, Some(9999));
    }

    #[test]
    fn test_update_oauth_tokens_preserves_refresh_token_when_not_rotated() {
        let mut vault = Vault::ephemeral();
        vault.set("OAUTH_KEY", "old-access-token").unwrap();
        vault
            .set_oauth_config(
                "OAUTH_KEY",
                Some(OAuthConfig {
                    token_url: "https://example.com/token".to_string(),
                    client_id: "id".to_string(),
                    client_secret: None,
                    refresh_token: "stays-the-same".to_string(),
                    expires_at: Some(100),
                }),
            )
            .unwrap();

        // Provider didn't rotate the refresh token — None means "keep it".
        vault
            .update_oauth_tokens("OAUTH_KEY", "new-access-token", None, Some(9999))
            .unwrap();

        assert_eq!(
            vault.oauth_config("OAUTH_KEY").unwrap().refresh_token,
            "stays-the-same"
        );
    }

    #[test]
    fn test_rotate_changes_value_keeps_placeholders() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "old-secret",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec![],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();

        let placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();

        vault.rotate("KEY", "new-secret").unwrap();

        // Placeholder unchanged
        let placeholder_after = vault.get_placeholder("KEY", "agent-1").unwrap();
        assert_eq!(placeholder, placeholder_after);

        // But resolves to new value
        let (_, value) = vault.resolve_placeholder(placeholder.as_str()).unwrap();
        assert_eq!(value.expose(), "new-secret");
    }

    #[test]
    fn test_remove_clears_credential_and_placeholders() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();
        let placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();

        vault.remove("KEY").unwrap();

        assert!(vault.get("KEY").is_none());
        assert!(vault.resolve_placeholder(placeholder.as_str()).is_none());
    }

    #[test]
    fn test_remove_nonexistent_fails() {
        let mut vault = Vault::ephemeral();
        let result = vault.remove("NOPE");
        assert!(matches!(
            result,
            Err(WardenError::CredentialNotFound { .. })
        ));
    }

    #[test]
    fn test_get_placeholder_unauthorized_agent() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "secret",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["allowed-agent".to_string()],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();

        let result = vault.get_placeholder("KEY", "unauthorized-agent");
        assert!(matches!(result, Err(WardenError::Unauthorized { .. })));
    }

    #[test]
    fn test_get_placeholder_open_access() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap(); // no allowed_agents = open

        // Any agent can get a placeholder
        let t1 = vault.get_placeholder("KEY", "any-agent").unwrap();
        assert!(t1.as_str().starts_with("wdn_placeholder_"));
    }

    #[test]
    fn test_resolve_placeholder_returns_value() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret-value").unwrap();
        let placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();

        let (name, value) = vault.resolve_placeholder(placeholder.as_str()).unwrap();
        assert_eq!(name, "KEY");
        assert_eq!(value.expose(), "secret-value");
    }

    #[test]
    fn test_resolve_placeholder_for_agent_succeeds_for_true_owner() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret-value").unwrap();
        let placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();

        let (name, value) = vault
            .resolve_placeholder_for_agent(placeholder.as_str(), "agent-1")
            .unwrap();
        assert_eq!(name, "KEY");
        assert_eq!(value.expose(), "secret-value");
    }

    #[test]
    fn test_resolve_placeholder_for_agent_rejects_stolen_token_under_different_claim() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret-value").unwrap();
        // Placeholder legitimately issued to agent-1...
        let placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();

        // ...but presented by a process claiming to be agent-2 (e.g. a
        // thief who copied the token and spoofed the x-warden-agent
        // header). Must be treated as unknown — no injection.
        assert!(vault
            .resolve_placeholder_for_agent(placeholder.as_str(), "agent-2")
            .is_none());
    }

    #[test]
    fn test_resolve_placeholder_for_agent_rejects_unknown_token() {
        let vault = Vault::ephemeral();
        assert!(vault
            .resolve_placeholder_for_agent("wdn_placeholder_0000000000000000", "agent-1")
            .is_none());
    }

    #[test]
    fn test_is_agent_authorized() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "s",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["a1".to_string()],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();

        assert!(vault.is_agent_authorized("KEY", "a1"));
        assert!(!vault.is_agent_authorized("KEY", "a2"));
        assert!(!vault.is_agent_authorized("NOPE", "a1"));
    }

    #[test]
    fn test_is_domain_allowed() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "s",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec![],
                    allowed_domains: vec!["api.openai.com".to_string()],
                    rate_limit: None,
                },
            )
            .unwrap();

        assert!(vault.is_domain_allowed("KEY", "api.openai.com"));
        assert!(!vault.is_domain_allowed("KEY", "evil.com"));
    }

    #[test]
    fn test_ephemeral_vault() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "val").unwrap();
        assert_eq!(vault.get("KEY").unwrap().expose(), "val");
        // No file I/O — save is a no-op
    }

    #[test]
    fn test_set_with_config() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "secret",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["bot".to_string()],
                    allowed_domains: vec!["api.example.com".to_string()],
                    rate_limit: Some(RateLimitConfig {
                        max_calls: 100,
                        per: TimePeriod::Hour,
                    }),
                },
            )
            .unwrap();

        let info = vault.list();
        assert_eq!(info[0].allowed_agents, vec!["bot"]);
        assert_eq!(info[0].allowed_domains, vec!["api.example.com"]);
        assert!(info[0].has_rate_limit);
    }

    #[test]
    fn test_rotate_nonexistent_fails() {
        let mut vault = Vault::ephemeral();
        let result = vault.rotate("NOPE", "val");
        assert!(matches!(
            result,
            Err(WardenError::CredentialNotFound { .. })
        ));
    }

    #[test]
    fn test_get_placeholder_nonexistent_credential() {
        let mut vault = Vault::ephemeral();
        let result = vault.get_placeholder("NOPE", "agent");
        assert!(matches!(
            result,
            Err(WardenError::CredentialNotFound { .. })
        ));
    }

    #[test]
    fn test_placeholder_per_agent_isolation() {
        let mut vault = Vault::ephemeral();
        vault.set("KEY", "secret").unwrap();

        let t1 = vault.get_placeholder("KEY", "agent-1").unwrap();
        let t2 = vault.get_placeholder("KEY", "agent-2").unwrap();

        assert_ne!(t1, t2);

        // Both resolve to the same credential
        let (n1, v1) = vault.resolve_placeholder(t1.as_str()).unwrap();
        let (n2, v2) = vault.resolve_placeholder(t2.as_str()).unwrap();
        assert_eq!(n1, "KEY");
        assert_eq!(n2, "KEY");
        assert_eq!(v1.expose(), v2.expose());
    }
}
