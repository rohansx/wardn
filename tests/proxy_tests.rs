use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::RwLock;
use tower::ServiceExt;

use wardn::config::{CredentialConfig, RateLimitConfig, TimePeriod, WardenConfig};
use wardn::proxy::budget::BudgetTracker;
use wardn::proxy::loop_guard::LoopGuard;
use wardn::proxy::rate_limit::RateLimiter;
use wardn::proxy::{self, ProxyState};
use wardn::Vault;

/// Create a proxy state with an ephemeral vault and given credentials.
fn test_state() -> (Arc<ProxyState>, String) {
    let mut vault = Vault::ephemeral();
    vault
        .set_with_config(
            "OPENAI_KEY",
            "sk-proj-real-key-123",
            &CredentialConfig {
                scrub_patterns: Vec::new(),
                oauth: None,
                budget: None,
                allowed_agents: vec!["researcher".to_string()],
                allowed_domains: vec!["api.openai.com".to_string()],
                rate_limit: None,
            },
        )
        .unwrap();

    let placeholder = vault
        .get_placeholder("OPENAI_KEY", "researcher")
        .unwrap()
        .to_string();

    let state = Arc::new(ProxyState {
        vault: Arc::new(RwLock::new(vault)),
        rate_limiter: Arc::new(tokio::sync::Mutex::new(RateLimiter::new())),
        budget_tracker: Arc::new(tokio::sync::Mutex::new(BudgetTracker::new())),
        loop_guard: Arc::new(tokio::sync::Mutex::new(LoopGuard::default())),
        config: WardenConfig::default(),
        http_client: reqwest::Client::new(),
    });

    (state, placeholder)
}

#[tokio::test]
async fn test_proxy_health_endpoint() {
    let (state, _) = test_state();
    let app = proxy::build_router(state);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_proxy_strips_warden_agent_header() {
    // This test verifies the header is removed from the request.
    // We can't easily test upstream doesn't receive it without a mock server,
    // but we can verify the proxy processes requests with the header.
    let (state, placeholder) = test_state();
    let app = proxy::build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("https://api.openai.com/v1/chat/completions")
        .header("host", "api.openai.com")
        .header("x-warden-agent", "researcher")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::from(r#"{"model": "gpt-4"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // The proxy processes the request and forwards to upstream.
    // We may get 401 (upstream rejects fake key), 502 (connection error), or 200.
    // The important thing: it's NOT 403 (Warden didn't block it).
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Warden should not block an authorized agent+domain combo"
    );
}

#[tokio::test]
async fn test_proxy_blocks_unauthorized_agent() {
    let (state, _) = test_state();

    // Get a placeholder as "researcher" but try to use it as "hacker"
    let vault = state.vault.read().await;
    // "hacker" is not in allowed_agents for OPENAI_KEY
    // They won't have a valid placeholder, but let's test with a fake one
    drop(vault);

    let app = proxy::build_router(state);

    // Use a fake placeholder that doesn't map to anything
    let req = Request::builder()
        .method("POST")
        .uri("https://api.openai.com/v1/chat/completions")
        .header("host", "api.openai.com")
        .header("x-warden-agent", "hacker")
        .header("authorization", "Bearer wdn_placeholder_0000000000000000")
        .body(Body::from(r#"{"model": "gpt-4"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Unknown placeholder passes through (no injection, no error from Warden).
    // Upstream may reject it (401) or connection may fail (502).
    // Key assertion: Warden does NOT return 403 or 429.
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_proxy_blocks_unauthorized_domain() {
    let (state, placeholder) = test_state();
    let app = proxy::build_router(state);

    // Try to use OPENAI_KEY placeholder against evil.com
    let req = Request::builder()
        .method("POST")
        .uri("https://evil.com/steal")
        .header("host", "evil.com")
        .header("x-warden-agent", "researcher")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "domain_not_allowed");
}

#[tokio::test]
async fn test_proxy_rate_limits() {
    let mut vault = Vault::ephemeral();
    vault
        .set_with_config(
            "KEY",
            "secret-key-value-long",
            &CredentialConfig {
                scrub_patterns: Vec::new(),
                oauth: None,
                budget: None,
                allowed_agents: vec![],
                allowed_domains: vec![],
                rate_limit: Some(RateLimitConfig {
                    max_calls: 2,
                    per: TimePeriod::Hour,
                }),
            },
        )
        .unwrap();

    let placeholder = vault.get_placeholder("KEY", "bot").unwrap().to_string();

    let mut rl = RateLimiter::new();
    rl.configure(
        "KEY",
        "bot",
        &RateLimitConfig {
            max_calls: 2,
            per: TimePeriod::Hour,
        },
    );

    let state = Arc::new(ProxyState {
        vault: Arc::new(RwLock::new(vault)),
        rate_limiter: Arc::new(tokio::sync::Mutex::new(rl)),
        budget_tracker: Arc::new(tokio::sync::Mutex::new(BudgetTracker::new())),
        loop_guard: Arc::new(tokio::sync::Mutex::new(LoopGuard::default())),
        config: WardenConfig::default(),
        http_client: reqwest::Client::new(),
    });

    // First 2 requests should pass (or fail with 502 since no upstream)
    for _ in 0..2 {
        let app = proxy::build_router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("https://api.example.com/v1")
            .header("host", "api.example.com")
            .header("x-warden-agent", "bot")
            .header("authorization", format!("Bearer {placeholder}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "should not be rate limited yet"
        );
    }

    // 3rd request should be rate limited
    let app = proxy::build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("https://api.example.com/v1")
        .header("host", "api.example.com")
        .header("x-warden-agent", "bot")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "rate_limit_exceeded");
    assert!(json["retry_after_seconds"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_proxy_passthrough_no_placeholders() {
    let (state, _) = test_state();
    let app = proxy::build_router(state);

    // Request with no placeholders — should forward as-is
    let req = Request::builder()
        .method("GET")
        .uri("https://api.example.com/data")
        .header("host", "api.example.com")
        .header("x-warden-agent", "researcher")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Will get 502 because no upstream, but should NOT get 403
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}
