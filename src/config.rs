use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::WardenError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WardenConfig {
    #[serde(default = "default_vault_path")]
    pub vault_path: String,

    #[serde(default)]
    pub credentials: HashMap<String, CredentialConfig>,

    /// Named upstream base URLs, keyed by a short provider slug.
    ///
    /// A request whose path starts with `/{slug}/...` is routed to
    /// `{upstream_base}/...` instead of being derived from the `Host`
    /// header. This is what lets a plain SDK base-URL override
    /// (`OPENAI_BASE_URL=http://127.0.0.1:7777/openai`) work — the SDK's
    /// `Host` header points at the local proxy itself, so it can't be used
    /// to pick the real upstream.
    #[serde(default = "default_upstreams")]
    pub upstreams: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    pub rate_limit: Option<RateLimitConfig>,

    #[serde(default)]
    pub allowed_agents: Vec<String>,

    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// A dollar-denominated spend cap, applied per agent (each agent
    /// authorized for this credential gets its own independent budget of
    /// this size — same per-agent-bucket model as `rate_limit`).
    #[serde(default)]
    pub budget: Option<BudgetConfig>,

    /// OAuth2 refresh_token-grant config, for credentials backed by a
    /// short-lived access token rather than a static API key. When set,
    /// the proxy refreshes the access token before it expires — see
    /// `proxy::oauth`.
    #[serde(default)]
    pub oauth: Option<OAuthConfig>,

    /// Regex patterns to redact from responses on requests that inject
    /// this credential — beyond the exact-value stripping every credential
    /// already gets. For catching *derived* secrets an upstream returns
    /// (e.g. a login endpoint echoing back a fresh session token) that
    /// wardn never injected and so wouldn't otherwise recognize. Matches
    /// are replaced with `[REDACTED]`, not a placeholder — this is a
    /// one-way defensive scrub, not something the agent can use again.
    /// Invalid patterns are skipped with a warning, not a hard error.
    #[serde(default)]
    pub scrub_patterns: Vec<String>,
}

/// OAuth2 refresh_token grant (RFC 6749 §6) config for one credential.
///
/// `refresh_token` and `client_secret` are stored as plain strings here —
/// unlike the credential's own `value`, they don't get the extra
/// zeroize-on-drop treatment `SensitiveString` provides, though they're
/// still only ever persisted inside the encrypted vault file, never in
/// plaintext on disk. A known, documented gap rather than an oversight.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuthConfig {
    pub token_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub refresh_token: String,
    /// Unix timestamp (seconds) when the current access token expires.
    /// `None` means "treat as already expired" — refresh on first use.
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// A dollar-denominated spend cap for one credential, applied per agent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BudgetConfig {
    pub max_usd: f64,

    #[serde(default)]
    pub window: BudgetWindow,

    /// Hard = block once the budget is exceeded. Soft = keep allowing
    /// requests but the overage is still tracked/loggable.
    #[serde(default)]
    pub mode: BudgetMode,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BudgetWindow {
    Hour,
    #[default]
    Day,
    Week,
    Month,
    /// Never resets — a lifetime cap on this credential/agent pair.
    Total,
}

impl BudgetWindow {
    /// Window length in seconds, or `None` for `Total` (never resets).
    pub fn as_seconds(&self) -> Option<u64> {
        match self {
            BudgetWindow::Hour => Some(3_600),
            BudgetWindow::Day => Some(86_400),
            BudgetWindow::Week => Some(7 * 86_400),
            BudgetWindow::Month => Some(30 * 86_400),
            BudgetWindow::Total => None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BudgetMode {
    #[default]
    Hard,
    Soft,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_calls: u32,
    pub per: TimePeriod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimePeriod {
    Second,
    Minute,
    Hour,
    Day,
}

impl TimePeriod {
    pub fn as_seconds(&self) -> u64 {
        match self {
            TimePeriod::Second => 1,
            TimePeriod::Minute => 60,
            TimePeriod::Hour => 3600,
            TimePeriod::Day => 86400,
        }
    }
}

fn default_vault_path() -> String {
    "~/.vibeguard/vault.enc".to_string()
}

/// Built-in provider slug → upstream base URL mappings, available even
/// without a `wardn.toml`. Users can override or extend these under
/// `[upstreams]`.
pub fn default_upstreams() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert(
        "anthropic".to_string(),
        "https://api.anthropic.com".to_string(),
    );
    map.insert("openai".to_string(), "https://api.openai.com".to_string());
    map
}

impl Default for WardenConfig {
    fn default() -> Self {
        Self {
            vault_path: default_vault_path(),
            credentials: HashMap::new(),
            upstreams: default_upstreams(),
        }
    }
}

impl WardenConfig {
    /// Load config from a TOML file. Expects a `[warden]` section.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| WardenError::Config(format!("failed to read {}: {e}", path.display())))?;
        Self::from_toml(&content)
    }

    /// Parse from a TOML string. Accepts either a top-level `[warden]` section
    /// or a flat warden config.
    pub fn from_toml(content: &str) -> crate::Result<Self> {
        // Try parsing as a full vibeguard.toml with [warden] section
        #[derive(Deserialize)]
        struct Wrapper {
            warden: Option<WardenConfig>,
        }

        if let Ok(wrapper) = toml::from_str::<Wrapper>(content) {
            if let Some(config) = wrapper.warden {
                return Ok(config);
            }
        }

        // Fall back to parsing as flat warden config
        toml::from_str::<WardenConfig>(content)
            .map_err(|e| WardenError::Config(format!("parse error: {e}")))
    }

    /// Expand `~` to the user's home directory.
    pub fn vault_path_expanded(&self) -> PathBuf {
        expand_tilde(&self.vault_path)
    }
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"

[warden.credentials.OPENAI_KEY]
rate_limit = { max_calls = 200, per = "hour" }
allowed_agents = ["researcher", "writer"]
allowed_domains = ["api.openai.com"]

[warden.credentials.ANTHROPIC_KEY]
rate_limit = { max_calls = 100, per = "hour" }
allowed_agents = ["researcher"]
allowed_domains = ["api.anthropic.com"]
"#;

        let config = WardenConfig::from_toml(toml).unwrap();
        assert_eq!(config.vault_path, "/tmp/vault.enc");
        assert_eq!(config.credentials.len(), 2);

        let openai = &config.credentials["OPENAI_KEY"];
        assert_eq!(openai.allowed_agents, vec!["researcher", "writer"]);
        assert_eq!(openai.allowed_domains, vec!["api.openai.com"]);
        assert_eq!(openai.rate_limit.as_ref().unwrap().max_calls, 200);
        assert!(openai.budget.is_none());
    }

    #[test]
    fn test_parse_budget_config() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"

[warden.credentials.OPENAI_KEY]
allowed_agents = ["bot"]
budget = { max_usd = 5.0, window = "day", mode = "hard" }
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        let budget = config.credentials["OPENAI_KEY"].budget.unwrap();
        assert_eq!(budget.max_usd, 5.0);
        assert_eq!(budget.window, BudgetWindow::Day);
        assert_eq!(budget.mode, BudgetMode::Hard);
    }

    #[test]
    fn test_budget_window_and_mode_default() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"

[warden.credentials.OPENAI_KEY]
budget = { max_usd = 10.0 }
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        let budget = config.credentials["OPENAI_KEY"].budget.unwrap();
        assert_eq!(budget.window, BudgetWindow::Day);
        assert_eq!(budget.mode, BudgetMode::Hard);
    }

    #[test]
    fn test_budget_window_as_seconds() {
        assert_eq!(BudgetWindow::Hour.as_seconds(), Some(3_600));
        assert_eq!(BudgetWindow::Day.as_seconds(), Some(86_400));
        assert_eq!(BudgetWindow::Week.as_seconds(), Some(7 * 86_400));
        assert_eq!(BudgetWindow::Month.as_seconds(), Some(30 * 86_400));
        assert_eq!(BudgetWindow::Total.as_seconds(), None);
    }

    #[test]
    fn test_budget_soft_mode_parses() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"

[warden.credentials.OPENAI_KEY]
budget = { max_usd = 10.0, mode = "soft", window = "total" }
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        let budget = config.credentials["OPENAI_KEY"].budget.unwrap();
        assert_eq!(budget.mode, BudgetMode::Soft);
        assert_eq!(budget.window, BudgetWindow::Total);
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        assert_eq!(config.vault_path, "/tmp/vault.enc");
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn test_default_config() {
        let config = WardenConfig::default();
        assert_eq!(config.vault_path, "~/.vibeguard/vault.enc");
        assert!(config.credentials.is_empty());
    }

    #[test]
    fn test_default_config_has_builtin_upstreams() {
        let config = WardenConfig::default();
        assert_eq!(
            config.upstreams.get("anthropic").map(String::as_str),
            Some("https://api.anthropic.com")
        );
        assert_eq!(
            config.upstreams.get("openai").map(String::as_str),
            Some("https://api.openai.com")
        );
    }

    #[test]
    fn test_toml_without_upstreams_gets_builtin_defaults() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        assert!(config.upstreams.contains_key("anthropic"));
    }

    #[test]
    fn test_toml_can_override_and_extend_upstreams() {
        let toml = r#"
[warden]
vault_path = "/tmp/vault.enc"

[warden.upstreams]
anthropic = "https://custom.example.com"
myapi = "https://internal.example.com"
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        assert_eq!(
            config.upstreams.get("anthropic").map(String::as_str),
            Some("https://custom.example.com")
        );
        assert_eq!(
            config.upstreams.get("myapi").map(String::as_str),
            Some("https://internal.example.com")
        );
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/.vibeguard/vault.enc");
        assert!(!expanded.to_str().unwrap().starts_with('~'));
        assert!(expanded.to_str().unwrap().ends_with(".vibeguard/vault.enc"));
    }

    #[test]
    fn test_expand_absolute_path() {
        let expanded = expand_tilde("/tmp/vault.enc");
        assert_eq!(expanded, PathBuf::from("/tmp/vault.enc"));
    }

    #[test]
    fn test_invalid_toml_returns_error() {
        let result = WardenConfig::from_toml("this is not valid toml {{{{");
        assert!(matches!(result, Err(WardenError::Config(_))));
    }

    #[test]
    fn test_time_period_seconds() {
        assert_eq!(TimePeriod::Second.as_seconds(), 1);
        assert_eq!(TimePeriod::Minute.as_seconds(), 60);
        assert_eq!(TimePeriod::Hour.as_seconds(), 3600);
        assert_eq!(TimePeriod::Day.as_seconds(), 86400);
    }

    #[test]
    fn test_parse_flat_config() {
        let toml = r#"
vault_path = "/tmp/vault.enc"

[credentials.MY_KEY]
allowed_agents = ["bot"]
allowed_domains = ["example.com"]
"#;
        let config = WardenConfig::from_toml(toml).unwrap();
        assert_eq!(config.vault_path, "/tmp/vault.enc");
        assert_eq!(config.credentials.len(), 1);
    }
}
