pub mod config;
pub mod daemon;
pub mod mcp;
pub mod migrate;
pub mod proxy;
pub mod vault;

pub use config::WardenConfig;
pub use vault::placeholder::PlaceholderToken;
pub use vault::Vault;

#[derive(Debug, thiserror::Error)]
pub enum WardenError {
    #[error("vault not found at {path}")]
    VaultNotFound { path: String },

    #[error("wrong passphrase or corrupted vault")]
    DecryptionFailed,

    #[error("credential '{name}' not found")]
    CredentialNotFound { name: String },

    #[error("agent '{agent_id}' not authorized for credential '{credential}'")]
    Unauthorized {
        agent_id: String,
        credential: String,
    },

    #[error("domain '{domain}' not allowed for credential '{credential}'")]
    DomainNotAllowed { domain: String, credential: String },

    #[error("rate limit exceeded for '{credential}' by agent '{agent_id}', retry after {retry_after_seconds}s")]
    RateLimitExceeded {
        credential: String,
        agent_id: String,
        retry_after_seconds: u64,
    },

    #[error("budget exceeded for '{credential}' by agent '{agent_id}': spent ${spent_usd:.4} of ${max_usd:.2}")]
    BudgetExceeded {
        credential: String,
        agent_id: String,
        spent_usd: f64,
        max_usd: f64,
    },

    #[error("agent '{agent_id}' repeated an identical request {repeat_count} times — possible stuck loop")]
    LoopDetected {
        agent_id: String,
        repeat_count: usize,
    },

    #[error("refusing to proxy request to {upstream} — that is wardn's own listen address; point the base URL at a provider prefix instead (e.g. http://127.0.0.1:7777/anthropic)")]
    SelfForward { upstream: String },

    #[error("OAuth token refresh failed for '{credential}': {reason}")]
    OAuthRefreshFailed { credential: String, reason: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("invalid vault format: {0}")]
    InvalidFormat(String),

    #[error("OS keychain error: {0}")]
    Keyring(String),
}

pub type Result<T> = std::result::Result<T, WardenError>;
