//! Local web dashboard served on the same daemon port as the proxy.
//!
//! The dashboard is purely a read-only view onto the running daemon —
//! no mutation paths, no agent credentials ever appear in responses.
//! All endpoints are local-only because the daemon is bound to loopback
//! by default. Reachable at `http://127.0.0.1:7777/ui` once the daemon
//! is up (`wardn serve` or via the daemon spawned by `wardn run`).
//!
//! Endpoints:
//!   GET /                -> redirects to /ui
//!   GET /ui              -> static HTML page
//!   GET /api/summary     -> one-shot payload: credentials, budgets, agents, audit tail, daemon info
//!   GET /api/credentials -> credential names + ACLs (never values)
//!   GET /api/audit       -> recent audit entries (newest first, ?limit=N)
//!   GET /api/budgets     -> per-credential spend against configured budgets

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::config::CredentialConfig;

use super::audit::AuditEntry;
use super::ProxyState;

const DASHBOARD_HTML: &str = include_str!("../../dashboard.html");

pub async fn ui_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        DASHBOARD_HTML,
    )
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
}

fn default_audit_limit() -> usize {
    50
}

#[derive(Debug, Serialize)]
pub struct CredentialView {
    name: String,
    allowed_agents: Vec<String>,
    allowed_domains: Vec<String>,
    has_rate_limit: bool,
    created_at: String,
    rotated_at: Option<String>,
    has_budget: bool,
}

#[derive(Debug, Serialize)]
pub struct SummaryResponse {
    daemon: DaemonInfo,
    credentials: Vec<CredentialView>,
    agents: Vec<String>,
    budgets: Vec<BudgetView>,
    audit: Vec<AuditEntry>,
}

#[derive(Debug, Serialize)]
pub struct DaemonInfo {
    host: String,
    port: u16,
    uptime_secs: u64,
    vault_path: Option<String>,
    audit_buffer_len: usize,
    audit_buffer_capacity: usize,
}

#[derive(Debug, Serialize)]
pub struct BudgetView {
    credential: String,
    agent: String,
    configured: bool,
    spent_usd: Option<f64>,
    max_usd: Option<f64>,
    remaining_usd: Option<f64>,
    window: Option<String>,
    mode: Option<String>,
}

pub async fn summary_handler(
    State(state): State<Arc<ProxyState>>,
) -> Result<Json<SummaryResponse>, (StatusCode, String)> {
    let creds = credential_views(&state).await?;
    let agents = collect_agents(&creds);
    let budgets = budget_views(&state, "cli").await;
    let (audit_len, audit_cap) = match state.audit.lock() {
        Ok(log) => (log.len(), log.capacity()),
        Err(poisoned) => {
            let log = poisoned.into_inner();
            (log.len(), log.capacity())
        }
    };
    let audit = match state.audit.lock() {
        Ok(log) => log.recent(50),
        Err(poisoned) => poisoned.into_inner().recent(50),
    };

    let daemon = DaemonInfo {
        host: state.host.clone(),
        port: state.port,
        uptime_secs: state.started_at.elapsed().as_secs(),
        vault_path: state.vault.read().await.path().map(|p| p.display().to_string()),
        audit_buffer_len: audit_len,
        audit_buffer_capacity: audit_cap,
    };

    Ok(Json(SummaryResponse {
        daemon,
        credentials: creds,
        agents,
        budgets,
        audit,
    }))
}

pub async fn credentials_handler(
    State(state): State<Arc<ProxyState>>,
) -> Result<Json<Vec<CredentialView>>, (StatusCode, String)> {
    let views = credential_views(&state).await?;
    Ok(Json(views))
}

pub async fn audit_handler(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntry>>, (StatusCode, String)> {
    let entries = match state.audit.lock() {
        Ok(log) => log.recent(params.limit),
        Err(poisoned) => poisoned.into_inner().recent(params.limit),
    };
    Ok(Json(entries))
}

pub async fn budgets_handler(
    State(state): State<Arc<ProxyState>>,
) -> Result<Json<Vec<BudgetView>>, (StatusCode, String)> {
    let views = budget_views(&state, "cli").await;
    Ok(Json(views))
}

async fn credential_views(
    state: &ProxyState,
) -> Result<Vec<CredentialView>, (StatusCode, String)> {
    let vault = state.vault.read().await;
    let list = vault.list();
    let mut out = Vec::with_capacity(list.len());
    for info in list {
        out.push(CredentialView {
            name: info.name.clone(),
            allowed_agents: info.allowed_agents.clone(),
            allowed_domains: info.allowed_domains.clone(),
            has_rate_limit: info.has_rate_limit,
            created_at: info.created_at.clone(),
            rotated_at: info.rotated_at.clone(),
            has_budget: vault.budget_config(&info.name).is_some(),
        });
    }
    Ok(out)
}

fn collect_agents(creds: &[CredentialView]) -> Vec<String> {
    let mut agents: Vec<String> = creds
        .iter()
        .flat_map(|c| c.allowed_agents.iter().cloned())
        .collect();
    agents.sort();
    agents.dedup();
    agents
}

async fn budget_views(state: &ProxyState, agent: &str) -> Vec<BudgetView> {
    let vault = state.vault.read().await;
    let creds = vault.list();
    let mut out = Vec::with_capacity(creds.len());
    for info in creds {
        match vault.budget_config(&info.name) {
            Some(cfg) => {
                let mut bt = state.budget_tracker.lock().await;
                bt.ensure_configured(&info.name, agent, *cfg);
                if let Some(status) = bt.status(&info.name, agent) {
                    out.push(BudgetView {
                        credential: info.name.clone(),
                        agent: agent.to_string(),
                        configured: true,
                        spent_usd: Some(status.spent_usd),
                        max_usd: Some(status.max_usd),
                        remaining_usd: Some(status.remaining_usd),
                        window: Some(format!("{:?}", status.window).to_lowercase()),
                        mode: Some(format!("{:?}", status.mode).to_lowercase()),
                    });
                } else {
                    out.push(BudgetView {
                        credential: info.name.clone(),
                        agent: agent.to_string(),
                        configured: true,
                        spent_usd: None,
                        max_usd: None,
                        remaining_usd: None,
                        window: None,
                        mode: None,
                    });
                }
            }
            None => out.push(BudgetView {
                credential: info.name.clone(),
                agent: agent.to_string(),
                configured: false,
                spent_usd: None,
                max_usd: None,
                remaining_usd: None,
                window: None,
                mode: None,
            }),
        }
    }
    out
}
// ============================================================================
// Mutation endpoints (POST/DELETE) — write to the encrypted vault.
//
// Read-only views (`summary`, `credentials`, `audit`, `budgets`) live above.
// These complement them: every endpoint here is callable only via loopback
// (default bind address) and returns a structured `{ok, error?, ...}` JSON
// payload — never the stored secret value, never another credential's data.
// ============================================================================

/// Maximum length of a credential name. Kept short on purpose — names end
/// up as env-var-style identifiers downstream (`OPENAI_KEY` etc).
pub const MAX_NAME_LEN: usize = 128;

/// Strict validator for credential names. Rejects anything that's not safe
/// to round-trip through env vars, file paths, and shell variables.
fn validate_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("name is required".into());
    }
    if name.len() > MAX_NAME_LEN {
        return Err(format!("name too long (max {MAX_NAME_LEN})"));
    }
    if let Some(c) = name.chars().find(|c| !is_name_char(*c)) {
        return Err(format!(
            "name contains forbidden character {c:?} — \
             allowed: A-Z, a-z, 0-9, _, -, ., @"
        ));
    }
    Ok(name.to_string())
}

/// Allowed characters in a credential name. Conservative set that stays
/// portable across shell, env-var, and JSON contexts.
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@')
}

#[derive(Debug, Deserialize)]
pub struct CreateCredentialBody {
    pub name: String,
    pub value: String,
    /// Optional. Empty/unset = any domain (with the same loud warning
    /// `wardn vault set` already emits in the CLI).
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RotateCredentialBody {
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct MutationOk {
    pub ok: bool,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<bool>,
}

fn dashboard_agent() -> String {
    "dashboard".to_string()
}

fn make_request_id() -> String {
    use rand::Rng;
    let b: [u8; 6] = rand::thread_rng().gen();
    hex::encode(b)
}

fn record_audit(
    state: &ProxyState,
    event: &str,
    credential: &str,
) {
    let entry = AuditEntry::new(make_request_id(), dashboard_agent(), event).credential(credential);
    match state.audit.lock() {
        Ok(mut log) => log.record(entry),
        Err(poisoned) => poisoned.into_inner().record(entry),
    }
}

/// POST /api/credentials — create or overwrite. Silently overwrites the
/// value of an existing credential (matching `wardn vault set` semantics);
/// allowed domains become a union (existing + new) so the dashboard never
/// accidentally narrows a previously-broad ACL. Returns 201 on create,
/// 200 on overwrite.
pub async fn create_credential_handler(
    State(state): State<Arc<ProxyState>>,
    Json(body): Json<CreateCredentialBody>,
) -> Result<(StatusCode, Json<MutationOk>), (StatusCode, String)> {
    let name = validate_name(&body.name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if body.value.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "value is required".to_string()));
    }

    let mut vault = state.vault.write().await;
    let existed = vault.get(&name).is_some();

    // Merge allowed_domains with whatever's already there rather than
    // overwriting — the dashboard mutator shouldn't silently strip ACLs
    // previously configured by `wardn vault set` or `wardn.toml`.
    let mut new_domains = vault
        .list()
        .into_iter()
        .find(|c| c.name == name)
        .map(|c| c.allowed_domains)
        .unwrap_or_default();
    for d in &body.allowed_domains {
        let d = d.trim();
        if !d.is_empty() && !new_domains.iter().any(|x| x == d) {
            new_domains.push(d.to_string());
        }
    }

    let cfg = CredentialConfig {
        scrub_patterns: Vec::new(),
        oauth: None,
        budget: vault.budget_config(&name).copied(),
        allowed_agents: vault
            .list()
            .into_iter()
            .find(|c| c.name == name)
            .map(|c| c.allowed_agents)
            .unwrap_or_default(),
        allowed_domains: new_domains,
        rate_limit: None, // rate limits live in wardn.toml, not the vault
    };

    vault
        .set_with_config(&name, &body.value, &cfg)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("vault.set failed: {e}")))?;

    drop(vault);

    record_audit(&state, if existed { "credential_rotated" } else { "credential_created" }, &name);

    let status = if existed { StatusCode::OK } else { StatusCode::CREATED };
    Ok((
        status,
        Json(MutationOk {
            ok: true,
            name,
            created: Some(!existed),
            rotated: Some(existed),
            removed: None,
        }),
    ))
}

/// POST /api/credentials/:name/rotate — change the value of an existing
/// credential. Placeholders stay valid (pointing placeholders at the new
/// real value is what `wardn vault rotate` does, see vault/mod.rs:230).
pub async fn rotate_credential_handler(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(body): Json<RotateCredentialBody>,
) -> Result<Json<MutationOk>, (StatusCode, String)> {
    let name = validate_name(&name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if body.value.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "value is required".to_string()));
    }

    let mut vault = state.vault.write().await;
    if vault.get(&name).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("credential '{name}' does not exist — create it first"),
        ));
    }
    vault
        .rotate(&name, &body.value)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("vault.rotate failed: {e}")))?;
    drop(vault);

    record_audit(&state, "credential_rotated", &name);

    Ok(Json(MutationOk {
        ok: true,
        name,
        created: None,
        rotated: Some(true),
        removed: None,
    }))
}

/// DELETE /api/credentials/:name — irreversible. Body is ignored.
pub async fn delete_credential_handler(
    State(state): State<Arc<ProxyState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<MutationOk>, (StatusCode, String)> {
    let name = validate_name(&name).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let mut vault = state.vault.write().await;
    if vault.get(&name).is_none() {
        return Err((StatusCode::NOT_FOUND, format!("credential '{name}' not found")));
    }
    vault
        .remove(&name)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("vault.remove failed: {e}")))?;
    drop(vault);

    record_audit(&state, "credential_deleted", &name);

    Ok(Json(MutationOk {
        ok: true,
        name,
        created: None,
        rotated: None,
        removed: Some(true),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BudgetConfig, BudgetMode, BudgetWindow, CredentialConfig, RateLimitConfig, TimePeriod,
        WardenConfig,
    };
    use crate::proxy::audit::AuditLog;
    use crate::proxy::budget::BudgetTracker;
    use crate::proxy::rate_limit::RateLimiter;
    use crate::vault::Vault;
    use std::time::Instant;
    use tokio::sync::{Mutex, RwLock};

    fn test_state() -> Arc<ProxyState> {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "OPENAI_KEY",
                "sk-proj-test-real-value",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: Some(BudgetConfig {
                        max_usd: 10.0,
                        window: BudgetWindow::Day,
                        mode: BudgetMode::Hard,
                    }),
                    allowed_agents: vec!["researcher".to_string(), "writer".to_string()],
                    allowed_domains: vec!["api.openai.com".to_string()],
                    rate_limit: Some(RateLimitConfig {
                        max_calls: 100,
                        per: TimePeriod::Hour,
                    }),
                },
            )
            .unwrap();

        Arc::new(ProxyState {
            vault: Arc::new(RwLock::new(vault)),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
            budget_tracker: Arc::new(Mutex::new(BudgetTracker::new())),
            loop_guard: Arc::new(Mutex::new(Default::default())),
            audit: Arc::new(std::sync::Mutex::new(AuditLog::new())),
            config: WardenConfig::default(),
            host: "127.0.0.1".to_string(),
            port: 7777,
            started_at: Instant::now(),
            http_client: reqwest::Client::new(),
        })
    }

    #[tokio::test]
    async fn test_credential_views_include_budget_flag() {
        let state = test_state();
        let views = credential_views(&state).await.unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].name, "OPENAI_KEY");
        assert!(views[0].has_budget);
        assert!(views[0].has_rate_limit);
        assert_eq!(views[0].allowed_agents.len(), 2);
    }

    #[test]
    fn test_collect_agents_dedupes() {
        let creds = vec![
            CredentialView {
                name: "A".into(),
                allowed_agents: vec!["researcher".into(), "writer".into()],
                allowed_domains: vec![],
                has_rate_limit: false,
                created_at: "now".into(),
                rotated_at: None,
                has_budget: false,
            },
            CredentialView {
                name: "B".into(),
                allowed_agents: vec!["writer".into(), "bot".into()],
                allowed_domains: vec![],
                has_rate_limit: false,
                created_at: "now".into(),
                rotated_at: None,
                has_budget: false,
            },
        ];
        let agents = collect_agents(&creds);
        assert_eq!(agents, vec!["bot", "researcher", "writer"]);
    }

    #[tokio::test]
    async fn test_budget_views_lists_known_credentials() {
        let state = test_state();
        let views = budget_views(&state, "cli").await;
        assert_eq!(views.len(), 1);
        let v = &views[0];
        assert_eq!(v.credential, "OPENAI_KEY");
        assert!(v.configured);
        assert_eq!(v.max_usd, Some(10.0));
        assert_eq!(v.spent_usd, Some(0.0));
    }

    #[tokio::test]
    async fn test_summary_endpoint_returns_daemon_metadata() {
        let state = test_state();
        let app = crate::proxy::build_router(state);
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .uri("/api/summary")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["daemon"]["uptime_secs"].is_number());
        assert!(parsed["credentials"].is_array());
        assert_eq!(parsed["credentials"][0]["name"], "OPENAI_KEY");
        assert!(parsed["audit"].is_array());
    }

    #[tokio::test]
    async fn test_ui_returns_html() {
        let state = test_state();
        let app = crate::proxy::build_router(state);
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .uri("/ui")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.starts_with("text/html"));
    }

    #[tokio::test]
    async fn test_root_redirects_to_ui() {
        let state = test_state();
        let app = crate::proxy::build_router(state);
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/ui");
    }

    #[tokio::test]
    async fn test_audit_endpoint_respects_limit() {
        let state = test_state();
        {
            let mut log = state.audit.lock().unwrap();
            for i in 0..10 {
                log.record(
                    AuditEntry::new(format!("r{i}"), "agent", "request_completed")
                        .status(200)
                        .cost(0.001),
                );
            }
        }
        let app = crate::proxy::build_router(state);
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .uri("/api/audit?limit=3")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0]["request_id"], "r9");
        assert_eq!(parsed[2]["request_id"], "r7");
    }

    // -------------------------------------------------------------------
    // Mutation endpoint tests (POST /api/credentials,
    //   POST /api/credentials/{name}/rotate,
    //   DELETE /api/credentials/{name}).
    //
    // These exercise the JSON shapes the dashboard frontend posts. They
    // don't go through any human input — what matters is: payload shape,
    // validation, status code, and audit-trail side effect.
    // -------------------------------------------------------------------

    // axum 0.8 takes a `Body` directly via the `Json` extractor — small
    // helpers below build one from a string without pulling in an extra
    // `http_body_util` round-trip.

    fn post(uri: &str, body: &'static str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    fn delete(uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_create_credential_happy_path() {
        use tower::ServiceExt;
        let state = test_state();
        let app = crate::proxy::build_router(state.clone());

        let body = r#"{"name":"NEW_KEY","value":"sk-new-real","allowed_domains":["api.example.com"]}"#;
        let resp = app.oneshot(post("/api/credentials", body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Persisted in vault
        {
            let v = state.vault.read().await;
            assert_eq!(v.get("NEW_KEY").unwrap().expose(), "sk-new-real");
        }

        // Audit recorded
        let log = state.audit.lock().unwrap();
        assert!(log.recent(50).iter().any(|e| e.event == "credential_created" && e.credential.as_deref() == Some("NEW_KEY")));
    }

    #[tokio::test]
    async fn test_create_credential_rejects_empty_name() {
        use tower::ServiceExt;
        let state = test_state();
        let app = crate::proxy::build_router(state);

        let body = r#"{"name":"","value":"sk-x"}"#;
        let resp = app.oneshot(post("/api/credentials", body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_credential_rejects_forbidden_character() {
        use tower::ServiceExt;
        let state = test_state();
        let app = crate::proxy::build_router(state);

        let body = r#"{"name":"BAD/NAME","value":"sk-x"}"#;
        let resp = app.oneshot(post("/api/credentials", body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_credential_overwrites_existing_value_returns_200() {
        use tower::ServiceExt;
        let state = test_state();
        let app = crate::proxy::build_router(state.clone());

        let body = r#"{"name":"OPENAI_KEY","value":"sk-newer"}"#;
        let resp = app.oneshot(post("/api/credentials", body)).await.unwrap();
        // Existing credential → 200, not 201
        assert_eq!(resp.status(), StatusCode::OK);

        let v = state.vault.read().await;
        assert_eq!(v.get("OPENAI_KEY").unwrap().expose(), "sk-newer");
    }

    #[tokio::test]
    async fn test_rotate_requires_existing_credential() {
        use tower::ServiceExt;
        let state = test_state();
        let app = crate::proxy::build_router(state);

        let body = r#"{"value":"sk-x"}"#;
        let resp = app
            .oneshot(post("/api/credentials/NO_SUCH_KEY/rotate", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rotate_updates_value_and_keeps_placeholder_stable() {
        use tower::ServiceExt;
        let state = test_state();
        // Capture the placeholder issued under "researcher" before rotating
        let placeholder_before = {
            let mut v = state.vault.write().await;
            v.get_placeholder("OPENAI_KEY", "researcher")
                .unwrap()
                .to_string()
        };

        let app = crate::proxy::build_router(state.clone());
        let body = r#"{"value":"sk-rotated-real"}"#;
        let resp = app
            .oneshot(post("/api/credentials/OPENAI_KEY/rotate", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Real value changed
        {
            let v = state.vault.read().await;
            assert_eq!(v.get("OPENAI_KEY").unwrap().expose(), "sk-rotated-real");
        }

        // Placeholder MUST be stable across rotation (this is the whole
        // point of `rotate` vs `set` — agents never need to restart).
        let placeholder_after = {
            let mut v = state.vault.write().await;
            v.get_placeholder("OPENAI_KEY", "researcher")
                .unwrap()
                .to_string()
        };
        assert_eq!(placeholder_before, placeholder_after);
    }

    #[tokio::test]
    async fn test_delete_removes_credential() {
        use tower::ServiceExt;
        let state = test_state();
        let app = crate::proxy::build_router(state.clone());

        let resp = app
            .oneshot(delete("/api/credentials/OPENAI_KEY"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let v = state.vault.read().await;
        assert!(v.get("OPENAI_KEY").is_none());

        let log = state.audit.lock().unwrap();
        assert!(log.recent(50).iter().any(|e| e.event == "credential_deleted"));
    }

    #[tokio::test]
    async fn test_delete_missing_credential_returns_404() {
        use tower::ServiceExt;
        let state = test_state();
        let app = crate::proxy::build_router(state);

        let resp = app
            .oneshot(delete("/api/credentials/NOT_THERE"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_validate_name_rejects_whitespace_and_empty() {
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
        assert!(validate_name("OPENAI KEY").is_err()); // space
        assert!(validate_name("OPENAI\nKEY").is_err()); // newline
        assert!(validate_name("OPENAI/KEY").is_err()); // slash
        assert_eq!(validate_name("OPENAI_KEY").unwrap(), "OPENAI_KEY");
        assert_eq!(validate_name("a@b.c").unwrap(), "a@b.c");
    }

    #[test]
    fn test_validate_name_enforces_length_cap() {
        let too_long = "A".repeat(MAX_NAME_LEN + 1);
        assert!(validate_name(&too_long).is_err());
        let just_ok = "A".repeat(MAX_NAME_LEN);
        assert!(validate_name(&just_ok).is_ok());
    }
}
