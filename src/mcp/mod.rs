pub mod tools;

use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use tokio::sync::{Mutex, RwLock};

use crate::proxy::rate_limit::RateLimiter;
use crate::vault::Vault;
use tools::*;

/// MCP server state for Warden.
///
/// Each MCP session is associated with an agent identity.
/// The agent_id is set at connection time and determines
/// which credentials the agent can access.
#[derive(Clone)]
pub struct WardenMcpServer {
    vault: Arc<RwLock<Vault>>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    agent_id: String,
    // Read by the rmcp `#[tool_handler]`/`#[tool_router]` macro expansion
    // (dispatches tool calls through it), not by any code in this file —
    // clippy's dead-code analysis doesn't see that usage.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[tool_handler]
impl ServerHandler for WardenMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "Warden credential isolation proxy. \
             Agents never see real API keys — only placeholder tokens. \
             Use get_credential_ref to get your placeholder, \
             list_credentials to see available credentials, \
             and check_rate_limit to see your remaining quota."
                .to_string(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::from_build_env();
        info
    }
}

#[tool_router]
impl WardenMcpServer {
    /// Get a placeholder token for a credential.
    ///
    /// Returns a unique placeholder that maps to the real credential value.
    /// The real value is never exposed — it is injected at the proxy layer.
    #[tool(
        description = "Get a placeholder token for a named credential. The placeholder is unique to your agent and can be used in API calls routed through Warden. The real credential is never returned."
    )]
    async fn get_credential_ref(
        &self,
        Parameters(params): Parameters<GetCredentialRefParams>,
    ) -> String {
        let mut vault = self.vault.write().await;
        match vault.get_placeholder(&params.credential_name, &self.agent_id) {
            Ok(token) => {
                tracing::info!(
                    agent = %self.agent_id,
                    credential = %params.credential_name,
                    "mcp: credential ref requested"
                );
                let resp = GetCredentialRefResponse {
                    credential: params.credential_name,
                    placeholder: token.to_string(),
                };
                serde_json::to_string_pretty(&resp)
                    .unwrap_or_else(|e| format!(r#"{{"error": "{}"}}"#, e))
            }
            Err(e) => {
                tracing::warn!(
                    agent = %self.agent_id,
                    credential = %params.credential_name,
                    error = %e,
                    "mcp: credential ref failed"
                );
                let resp = ErrorResponse {
                    error: e.to_string(),
                };
                serde_json::to_string_pretty(&resp)
                    .unwrap_or_else(|e| format!(r#"{{"error": "{}"}}"#, e))
            }
        }
    }

    /// List credentials available to the calling agent.
    ///
    /// Returns credential names and metadata. Never returns actual values.
    #[tool(
        description = "List all credentials your agent is authorized to access. Returns names and metadata only — never actual secret values."
    )]
    async fn list_credentials(
        &self,
        Parameters(_params): Parameters<ListCredentialsParams>,
    ) -> String {
        let vault = self.vault.read().await;
        tracing::info!(agent = %self.agent_id, "mcp: credentials listed");
        let all = vault.list();

        let credentials: Vec<CredentialEntry> = all
            .into_iter()
            .filter(|info| {
                info.allowed_agents.is_empty() || info.allowed_agents.contains(&self.agent_id)
            })
            .map(|info| CredentialEntry {
                name: info.name,
                allowed_agents: info.allowed_agents,
                allowed_domains: info.allowed_domains,
                has_rate_limit: info.has_rate_limit,
            })
            .collect();

        let resp = ListCredentialsResponse { credentials };
        serde_json::to_string_pretty(&resp).unwrap_or_else(|e| format!(r#"{{"error": "{}"}}"#, e))
    }

    /// Check rate limit status for a credential.
    ///
    /// Returns remaining quota, limit, and period.
    #[tool(
        description = "Check your remaining rate limit quota for a credential. Returns how many calls you have left and when the limit resets."
    )]
    async fn check_rate_limit(
        &self,
        Parameters(params): Parameters<CheckRateLimitParams>,
    ) -> String {
        tracing::info!(
            agent = %self.agent_id,
            credential = %params.credential_name,
            "mcp: rate limit checked"
        );
        let mut rl = self.rate_limiter.lock().await;
        match rl.status(&params.credential_name, &self.agent_id) {
            Some(status) => {
                let period = if status.period_seconds == 1 {
                    "second".to_string()
                } else if status.period_seconds == 60 {
                    "minute".to_string()
                } else if status.period_seconds == 3600 {
                    "hour".to_string()
                } else if status.period_seconds == 86400 {
                    "day".to_string()
                } else {
                    format!("{}s", status.period_seconds)
                };

                let resp = CheckRateLimitResponse {
                    credential: params.credential_name,
                    remaining: status.remaining,
                    limit: status.limit,
                    period,
                    retry_after_seconds: status.retry_after_seconds,
                };
                serde_json::to_string_pretty(&resp)
                    .unwrap_or_else(|e| format!(r#"{{"error": "{}"}}"#, e))
            }
            None => {
                let resp = CheckRateLimitResponse {
                    credential: params.credential_name,
                    remaining: u32::MAX,
                    limit: 0,
                    period: "unlimited".to_string(),
                    retry_after_seconds: None,
                };
                serde_json::to_string_pretty(&resp)
                    .unwrap_or_else(|e| format!(r#"{{"error": "{}"}}"#, e))
            }
        }
    }
}

impl WardenMcpServer {
    /// Create a new MCP server instance for a specific agent.
    pub fn new(
        vault: Arc<RwLock<Vault>>,
        rate_limiter: Arc<Mutex<RateLimiter>>,
        agent_id: String,
    ) -> Self {
        let tool_router = Self::tool_router();
        Self {
            vault,
            rate_limiter,
            agent_id,
            tool_router,
        }
    }

    /// Serve over stdio transport (for Claude Code, Cursor, etc.).
    pub async fn serve_stdio(
        vault: Arc<RwLock<Vault>>,
        rate_limiter: Arc<Mutex<RateLimiter>>,
        agent_id: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Self::new(vault, rate_limiter, agent_id);
        let transport = rmcp::transport::stdio();
        let service = server.serve(transport).await?;
        service.waiting().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialConfig, RateLimitConfig, TimePeriod};

    async fn setup_server() -> WardenMcpServer {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "OPENAI_KEY",
                "sk-proj-real-key-123",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["researcher".to_string(), "writer".to_string()],
                    allowed_domains: vec!["api.openai.com".to_string()],
                    rate_limit: Some(RateLimitConfig {
                        max_calls: 200,
                        per: TimePeriod::Hour,
                    }),
                },
            )
            .unwrap();
        vault
            .set_with_config(
                "ANTHROPIC_KEY",
                "sk-ant-456",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["researcher".to_string()],
                    allowed_domains: vec!["api.anthropic.com".to_string()],
                    rate_limit: None,
                },
            )
            .unwrap();

        let vault = Arc::new(RwLock::new(vault));

        let mut rl = RateLimiter::new();
        rl.configure(
            "OPENAI_KEY",
            "researcher",
            &RateLimitConfig {
                max_calls: 200,
                per: TimePeriod::Hour,
            },
        );
        let rate_limiter = Arc::new(Mutex::new(rl));

        WardenMcpServer::new(vault, rate_limiter, "researcher".to_string())
    }

    #[tokio::test]
    async fn test_get_credential_ref() {
        let server = setup_server().await;
        let params = Parameters(GetCredentialRefParams {
            credential_name: "OPENAI_KEY".to_string(),
        });

        let result = server.get_credential_ref(params).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["credential"], "OPENAI_KEY");
        assert!(json["placeholder"]
            .as_str()
            .unwrap()
            .starts_with("wdn_placeholder_"));
        // No real key in the response
        assert!(!result.contains("sk-proj-real-key-123"));
    }

    #[tokio::test]
    async fn test_get_credential_ref_idempotent() {
        let server = setup_server().await;

        let r1 = server
            .get_credential_ref(Parameters(GetCredentialRefParams {
                credential_name: "OPENAI_KEY".to_string(),
            }))
            .await;
        let r2 = server
            .get_credential_ref(Parameters(GetCredentialRefParams {
                credential_name: "OPENAI_KEY".to_string(),
            }))
            .await;

        let j1: serde_json::Value = serde_json::from_str(&r1).unwrap();
        let j2: serde_json::Value = serde_json::from_str(&r2).unwrap();
        assert_eq!(j1["placeholder"], j2["placeholder"]);
    }

    #[tokio::test]
    async fn test_get_credential_ref_unauthorized() {
        let server = setup_server().await;
        // "researcher" is not authorized for a credential that doesn't exist
        let result = server
            .get_credential_ref(Parameters(GetCredentialRefParams {
                credential_name: "NONEXISTENT".to_string(),
            }))
            .await;

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_list_credentials_filters_by_agent() {
        let server = setup_server().await;
        let result = server
            .list_credentials(Parameters(ListCredentialsParams {}))
            .await;

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        let creds = json["credentials"].as_array().unwrap();

        // "researcher" should see both OPENAI_KEY and ANTHROPIC_KEY
        assert_eq!(creds.len(), 2);

        let names: Vec<&str> = creds.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"OPENAI_KEY"));
        assert!(names.contains(&"ANTHROPIC_KEY"));

        // No credential values in the response
        assert!(!result.contains("sk-proj"));
        assert!(!result.contains("sk-ant"));
    }

    #[tokio::test]
    async fn test_list_credentials_hides_unauthorized() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "SECRET_KEY",
                "secret",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["admin-only".to_string()],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();
        vault.set("OPEN_KEY", "open").unwrap(); // no allowed_agents = open

        let vault = Arc::new(RwLock::new(vault));
        let rl = Arc::new(Mutex::new(RateLimiter::new()));
        let server = WardenMcpServer::new(vault, rl, "random-agent".to_string());

        let result = server
            .list_credentials(Parameters(ListCredentialsParams {}))
            .await;

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        let creds = json["credentials"].as_array().unwrap();

        // Should only see OPEN_KEY (open access), not SECRET_KEY
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["name"], "OPEN_KEY");
    }

    #[tokio::test]
    async fn test_check_rate_limit_configured() {
        let server = setup_server().await;
        let result = server
            .check_rate_limit(Parameters(CheckRateLimitParams {
                credential_name: "OPENAI_KEY".to_string(),
            }))
            .await;

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["credential"], "OPENAI_KEY");
        assert_eq!(json["limit"], 200);
        assert_eq!(json["remaining"], 200);
        assert_eq!(json["period"], "hour");
        assert!(json.get("retry_after_seconds").is_none() || json["retry_after_seconds"].is_null());
    }

    #[tokio::test]
    async fn test_check_rate_limit_unconfigured() {
        let server = setup_server().await;
        let result = server
            .check_rate_limit(Parameters(CheckRateLimitParams {
                credential_name: "ANTHROPIC_KEY".to_string(),
            }))
            .await;

        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["period"], "unlimited");
    }

    #[tokio::test]
    async fn test_no_real_credentials_in_any_response() {
        let server = setup_server().await;

        // Call all three tools
        let r1 = server
            .get_credential_ref(Parameters(GetCredentialRefParams {
                credential_name: "OPENAI_KEY".to_string(),
            }))
            .await;
        let r2 = server
            .list_credentials(Parameters(ListCredentialsParams {}))
            .await;
        let r3 = server
            .check_rate_limit(Parameters(CheckRateLimitParams {
                credential_name: "OPENAI_KEY".to_string(),
            }))
            .await;

        // None of the responses should contain real credential values
        for resp in [&r1, &r2, &r3] {
            assert!(
                !resp.contains("sk-proj-real-key-123"),
                "leaked OPENAI_KEY in: {resp}"
            );
            assert!(
                !resp.contains("sk-ant-456"),
                "leaked ANTHROPIC_KEY in: {resp}"
            );
        }
    }

    #[tokio::test]
    async fn test_server_info() {
        let server = setup_server().await;
        let info = server.get_info();

        assert!(info.instructions.is_some());
        assert!(info.instructions.unwrap().contains("Warden"));
    }
}
