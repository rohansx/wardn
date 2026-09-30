pub mod audit;
pub mod budget;
pub mod cost;
pub mod dashboard;
pub mod inject;
pub mod loop_guard;
pub mod oauth;
pub mod rate_limit;
pub mod route;
pub mod stream;
pub mod strip;

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{any, get};
use axum::Router;
use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::config::WardenConfig;
use crate::vault::Vault;
use crate::WardenError;
use audit::AuditEntry;
use loop_guard::LoopGuard;
use rate_limit::RateLimiter;
use stream::StreamingStripper;

/// Shared state for the proxy server.
pub struct ProxyState {
    pub vault: Arc<RwLock<Vault>>,
    pub rate_limiter: Arc<tokio::sync::Mutex<RateLimiter>>,
    pub budget_tracker: Arc<tokio::sync::Mutex<budget::BudgetTracker>>,
    pub loop_guard: Arc<tokio::sync::Mutex<LoopGuard>>,
    pub audit: Arc<std::sync::Mutex<audit::AuditLog>>,
    pub config: WardenConfig,
    pub host: String,
    pub port: u16,
    pub started_at: Instant,
    pub http_client: reqwest::Client,
}

const AGENT_HEADER: &str = "x-warden-agent";

/// Generate a short unique request ID for audit trail correlation.
fn generate_request_id() -> String {
    use rand::Rng;
    let bytes: [u8; 6] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Build the proxy router.
pub fn build_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/_wardn/budget", get(budget_status_handler))
        // Dashboard routes — registered directly on the main router (NOT
        // via .nest(), which would add an unwanted prefix). The dashboard
        // is purely read-only — see src/proxy/dashboard.rs for endpoints.
        .route("/ui", get(dashboard::ui_handler))
        .route("/", get(|| async { Redirect::to("/ui") }))
        .route("/api/summary", get(dashboard::summary_handler))
        .route("/api/credentials", get(dashboard::credentials_handler))
        .route(
            "/api/credentials",
            axum::routing::post(dashboard::create_credential_handler),
        )
        .route(
            "/api/credentials/{name}/rotate",
            axum::routing::post(dashboard::rotate_credential_handler),
        )
        .route(
            "/api/credentials/{name}",
            axum::routing::delete(dashboard::delete_credential_handler),
        )
        .route("/api/audit", get(dashboard::audit_handler))
        .route("/api/budgets", get(dashboard::budgets_handler))
        .fallback(any(proxy_handler))
        .with_state(state)
}

fn record_audit(state: &ProxyState, entry: AuditEntry) {
    match state.audit.lock() {
        Ok(mut log) => log.record(entry),
        Err(poisoned) => {
            let mut log = poisoned.into_inner();
            log.record(entry);
        }
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[derive(Debug, Deserialize)]
struct BudgetStatusQuery {
    agent: String,
}

/// Live budget status for every credential an agent can use — the source
/// `wardn budget status` queries, since spend is tracked in the running
/// daemon's `BudgetTracker`, not in the vault (which only holds the config).
async fn budget_status_handler(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<BudgetStatusQuery>,
) -> impl IntoResponse {
    {
        let mut vault = state.vault.write().await;
        if let Err(e) = vault.reload() {
            tracing::warn!(error = %e, "vault reload failed, using cached state");
        }
    }

    let vault = state.vault.read().await;
    let mut bt = state.budget_tracker.lock().await;

    let credentials: Vec<serde_json::Value> = vault
        .list()
        .into_iter()
        .filter(|info| {
            info.allowed_agents.is_empty() || info.allowed_agents.contains(&params.agent)
        })
        .map(|info| match vault.budget_config(&info.name) {
            Some(cfg) => {
                bt.ensure_configured(&info.name, &params.agent, *cfg);
                let status = bt.status(&info.name, &params.agent).unwrap();
                serde_json::json!({
                    "credential": info.name,
                    "configured": true,
                    "spent_usd": status.spent_usd,
                    "max_usd": status.max_usd,
                    "remaining_usd": status.remaining_usd,
                    "window": format!("{:?}", status.window).to_lowercase(),
                    "mode": format!("{:?}", status.mode).to_lowercase(),
                })
            }
            None => serde_json::json!({
                "credential": info.name,
                "configured": false,
            }),
        })
        .collect();

    axum::Json(serde_json::json!({
        "agent": params.agent,
        "credentials": credentials,
    }))
}

async fn proxy_handler(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response {
    // Snapshot the agent identity BEFORE `req` is moved into
    // handle_proxy_request — we need it to attribute error events to the
    // right agent in the audit log.
    let agent_for_audit = req
        .headers()
        .get(AGENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous")
        .to_string();
    let state_for_error_audit = state.clone();

    match handle_proxy_request(state, req).await {
        Ok(response) => response,
        Err(e) => {
            let event = match &e {
                WardenError::Unauthorized { .. } => "request_denied",
                WardenError::DomainNotAllowed { .. } => "domain_denied",
                _ => "request_error",
            };
            // A fresh request_id here — the original id (used inside the
            // inner handler) is gone with the consumed `req`, and the only
            // purpose of this row is signalling "this request failed"; the
            // corresponding tracing event carries the correlated id.
            record_audit(
                &state_for_error_audit,
                AuditEntry::new(generate_request_id(), &agent_for_audit, event),
            );
            tracing::warn!(error = %e, "proxy request failed");
            error_response(e)
        }
    }
}

async fn handle_proxy_request(
    state: Arc<ProxyState>,
    req: Request<Body>,
) -> crate::Result<Response> {
    let request_id = generate_request_id();

    // 1. Extract agent identity from X-Warden-Agent header
    let agent_id = req
        .headers()
        .get(AGENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "anonymous".to_string());

    // 2. Resolve where this request actually goes.
    //
    // A base-URL SDK override (e.g. ANTHROPIC_BASE_URL=http://127.0.0.1:7777/anthropic)
    // sends `Host: 127.0.0.1:7777` — the proxy's own address — so the Host
    // header alone can't identify the upstream in that case. route::resolve_route
    // first checks for a configured provider-prefix (`/anthropic/...`,
    // `/openai/...`) and only falls back to Host-header routing for plain
    // forward-proxy usage.
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();

    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.clone());

    // The daemon listens on plain HTTP, so an origin-form request (the
    // normal client shape) necessarily arrived over http; a client sending
    // absolute-form URIs (real forward-proxy style) may carry an explicit
    // scheme. Use it when present — never assume https, which made every
    // http request to the proxy fail.
    let scheme = req.uri().scheme_str().unwrap_or("http").to_string();

    let route = route::resolve_route(&path_and_query, &host, &scheme, &state.config.upstreams);
    let domain = route.domain.clone();

    // Refuse to forward to our own listen address. A base-URL override
    // without a provider prefix (e.g. `ANTHROPIC_BASE_URL=http://127.0.0.1:7777`)
    // resolves, via Host-header fallback, back to this daemon — forwarding
    // would loop the request through the proxy until the loop guard trips.
    if route.provider_slug.is_none()
        && route::is_self_upstream(&route.upstream_base, &state.host, state.port)
    {
        tracing::warn!(
            request_id = %request_id,
            agent = %agent_id,
            method = %method,
            path = %path,
            upstream = %route.upstream_base,
            "refusing to forward to own listen address"
        );
        return Err(WardenError::SelfForward {
            upstream: route.upstream_base.clone(),
        });
    }

    tracing::info!(
        request_id = %request_id,
        agent = %agent_id,
        method = %method,
        domain = %domain,
        path = %path,
        upstream = %route.upstream_base,
        "proxy request received"
    );

    // 3. Read the request parts
    let (mut parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024) // 10MB limit
        .await
        .map_err(|e| WardenError::Io(std::io::Error::other(e)))?;

    // 4. Strip X-Warden-Agent header (must not reach upstream)
    parts.headers.remove(AGENT_HEADER);

    // 4.5. Loop/runaway detection — the SAME request (method+domain+path+
    // body) repeated many times by the same agent in a short window trips
    // an early stop, independent of and before any budget check. This
    // catches a stuck retry loop even when no credential/budget is
    // involved at all, or before a generous budget would otherwise catch it.
    {
        let fp = loop_guard::fingerprint(&method, &domain, &path, &body_bytes);
        let mut lg = state.loop_guard.lock().await;
        if let Some(repeat_count) = lg.record_and_check(&agent_id, fp) {
            tracing::warn!(
                request_id = %request_id,
                agent = %agent_id,
                repeat_count = %repeat_count,
                domain = %domain,
                path = %path,
                "loop detected — blocking request"
            );
            record_audit(
                &state,
                AuditEntry::new(&request_id, &agent_id, "loop_detected")
                    .request(&method, &domain, &path),
            );
            return Err(WardenError::LoopDetected {
                agent_id: agent_id.clone(),
                repeat_count,
            });
        }
    }

    // Reload the vault from disk (cheap — reuses the derived key, no KDF)
    // so a CLI-driven change in another process — `wardn budget set`,
    // `vault rotate`, etc. — takes effect immediately on this already-
    // running daemon rather than only after a restart. Briefly exclusive,
    // then downgraded to a shared read lock for the rest of the request.
    {
        let mut vault = state.vault.write().await;
        if let Err(e) = vault.reload() {
            tracing::warn!(request_id = %request_id, error = %e, "vault reload failed, using cached state");
        }

        // OAuth refresh: any OAuth-backed credential whose access token is
        // near/past expiry gets refreshed now, BEFORE injection, so the
        // value about to be injected is current. This checks every
        // OAuth-backed credential in the vault (not just ones this request
        // happens to use) — simpler than threading refresh through the
        // placeholder-scanning injection path, and cheap in the common
        // case (no network call at all unless a token is actually close to
        // expiring).
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        for cred_name in vault.oauth_credential_names() {
            let Some(cfg) = vault.oauth_config(&cred_name).cloned() else {
                continue;
            };
            if !oauth::needs_refresh(&cfg, now_unix) {
                continue;
            }
            match oauth::refresh_access_token(&state.http_client, &cred_name, &cfg, now_unix).await
            {
                Ok(tokens) => {
                    tracing::info!(
                        request_id = %request_id,
                        credential = %cred_name,
                        "oauth access token refreshed"
                    );
                    if let Err(e) = vault.update_oauth_tokens(
                        &cred_name,
                        &tokens.access_token,
                        tokens.refresh_token.as_deref(),
                        tokens.expires_at,
                    ) {
                        tracing::warn!(
                            request_id = %request_id,
                            credential = %cred_name,
                            error = %e,
                            "failed to persist refreshed oauth token"
                        );
                    }
                }
                Err(e) => {
                    // Don't fail the whole request over an unrelated
                    // credential's refresh failure — it may not even be the
                    // one this request needs. The stale token stays in
                    // place; injection/upstream will surface the real
                    // failure if it's actually used.
                    tracing::warn!(
                        request_id = %request_id,
                        credential = %cred_name,
                        error = %e,
                        "oauth token refresh failed"
                    );
                }
            }
        }
    }

    // 5. Inject credentials into headers
    let vault = state.vault.read().await;
    let mut all_injected = Vec::new();

    let mut new_headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        let value_str = value.to_str().unwrap_or_default();
        let (injected_value, injected_creds) =
            inject::inject_header_value(value_str, &agent_id, &domain, &vault)?;
        all_injected.extend(injected_creds);
        if let Ok(hv) = HeaderValue::from_str(&injected_value) {
            new_headers.insert(name.clone(), hv);
        }
    }
    parts.headers = new_headers;

    // 6. Inject credentials into body
    let (injected_body, body_injected) =
        inject::inject_body(&body_bytes, &agent_id, &domain, &vault)?;
    all_injected.extend(body_injected);

    // Log credential injection events
    for cred_name in &all_injected {
        tracing::info!(
            request_id = %request_id,
            agent = %agent_id,
            credential = %cred_name,
            domain = %domain,
            "credential injected"
        );
        record_audit(
            &state,
            AuditEntry::new(&request_id, &agent_id, "credential_injected")
                .credential(cred_name)
                .request(&method, &domain, &path),
        );
    }

    // 7. Rate limit check for each injected credential
    {
        let mut rl = state.rate_limiter.lock().await;
        for cred_name in &all_injected {
            if let Err(retry_after) = rl.check(cred_name, &agent_id) {
                tracing::warn!(
                    request_id = %request_id,
                    agent = %agent_id,
                    credential = %cred_name,
                    retry_after_seconds = %retry_after,
                    "rate limit exceeded"
                );
                record_audit(
                    &state,
                    AuditEntry::new(&request_id, &agent_id, "rate_limit")
                        .credential(cred_name)
                        .request(&method, &domain, &path),
                );
                return Err(WardenError::RateLimitExceeded {
                    credential: cred_name.clone(),
                    agent_id: agent_id.clone(),
                    retry_after_seconds: retry_after,
                });
            }
        }
    }

    // 7.5. Budget check for each injected credential. Reads the vault's
    // CURRENT budget config live on every request (not a snapshot taken at
    // daemon startup), so `wardn budget set` takes effect immediately.
    {
        let mut bt = state.budget_tracker.lock().await;
        for cred_name in &all_injected {
            let Some(budget_config) = vault.budget_config(cred_name) else {
                continue;
            };
            bt.ensure_configured(cred_name, &agent_id, *budget_config);

            match bt.check(cred_name, &agent_id) {
                budget::BudgetCheck::Ok => {}
                budget::BudgetCheck::ExceededSoft { spent_usd, max_usd } => {
                    tracing::warn!(
                        request_id = %request_id,
                        agent = %agent_id,
                        credential = %cred_name,
                        spent_usd = %spent_usd,
                        max_usd = %max_usd,
                        "budget exceeded (soft mode — allowing request)"
                    );
                    record_audit(
                        &state,
                        AuditEntry::new(&request_id, &agent_id, "budget_exceeded")
                            .credential(cred_name)
                            .request(&method, &domain, &path),
                    );
                }
                budget::BudgetCheck::Exceeded { spent_usd, max_usd } => {
                    tracing::warn!(
                        request_id = %request_id,
                        agent = %agent_id,
                        credential = %cred_name,
                        spent_usd = %spent_usd,
                        max_usd = %max_usd,
                        "budget exceeded — blocking request"
                    );
                    record_audit(
                        &state,
                        AuditEntry::new(&request_id, &agent_id, "budget_exceeded")
                            .credential(cred_name)
                            .request(&method, &domain, &path),
                    );
                    return Err(WardenError::BudgetExceeded {
                        credential: cred_name.clone(),
                        agent_id: agent_id.clone(),
                        spent_usd,
                        max_usd,
                    });
                }
            }
        }
    }

    drop(vault); // release read lock before forwarding

    // 8. Build upstream URL from the resolved route (not the raw Host header —
    // see the routing comment above for why).
    let upstream_url = format!("{}{}", route.upstream_base, route.upstream_path_and_query);

    // 9. Forward request to upstream.
    // Capture the HTTP method as a string BEFORE the `axum::http::Method`
    // gets translated/consumed into the reqwest request — the body_stream
    // audit closure needs `log_method` after the response has fully
    // arrived and the original `Method` is gone.
    let log_method = parts.method.to_string();
    let method = match parts.method {
        axum::http::Method::GET => reqwest::Method::GET,
        axum::http::Method::POST => reqwest::Method::POST,
        axum::http::Method::PUT => reqwest::Method::PUT,
        axum::http::Method::DELETE => reqwest::Method::DELETE,
        axum::http::Method::PATCH => reqwest::Method::PATCH,
        axum::http::Method::HEAD => reqwest::Method::HEAD,
        axum::http::Method::OPTIONS => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut upstream_req = state.http_client.request(method, &upstream_url);

    // Copy headers (skip host — reqwest sets it)
    let mut reqwest_headers = reqwest::header::HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if name.as_str() == "host" {
            continue;
        }
        if let Ok(rn) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(rv) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                reqwest_headers.insert(rn, rv);
            }
        }
    }
    upstream_req = upstream_req.headers(reqwest_headers);

    // Captured before injected_body is moved into the request — used for
    // post-response cost estimation (the fallback byte-based token
    // estimate, and a best-effort "model" from the request if the
    // response doesn't carry one).
    let request_body_len = injected_body.len();
    let request_model = cost::extract_model_from_json(&injected_body);

    upstream_req = upstream_req.body(injected_body);

    let upstream_resp = upstream_req
        .send()
        .await
        .map_err(|e| WardenError::Io(std::io::Error::other(e)))?;

    // 10. Read upstream response status/headers. The body is NOT buffered —
    // it's streamed through a StreamingStripper below, so SSE and other
    // chunked responses forward incrementally instead of waiting for the
    // full response (and so we never lie about content-length for a body
    // we're about to re-chunk).
    let resp_status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // Build the (real_value, placeholder, credential_name) pairs once —
    // both header stripping and the streaming body stripper reuse them, so
    // the vault is locked exactly once here rather than per-header/per-chunk.
    // Scrub-pattern regexes (for derived secrets wardn never injected, e.g.
    // a login endpoint's fresh session token) are compiled from the same
    // injected-credential set.
    let (pairs, scrub_regexes) = {
        let vault = state.vault.read().await;
        (
            strip::build_replacement_pairs(&agent_id, &all_injected, &vault),
            strip::compile_scrub_regexes(&all_injected, &vault),
        )
    };

    // 11. Build response status + headers.
    let mut response = Response::builder()
        .status(StatusCode::from_u16(resp_status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY));

    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str();
        // These describe the upstream's original framing, which no longer
        // applies once the body is re-chunked below.
        if matches!(
            name_str.to_ascii_lowercase().as_str(),
            "content-length" | "transfer-encoding" | "content-encoding"
        ) {
            continue;
        }
        let (stripped_value, _) =
            strip::apply_pairs_str(value.to_str().unwrap_or_default(), &pairs);
        if let Ok(hv) = HeaderValue::from_str(&stripped_value) {
            response = response.header(name_str, hv);
        }
    }

    // 12. Stream the body through the stripper. Credential-stripped /
    // request-completed audit logs fire once the stream drains, since that's
    // the first point the true stripped-credential set is known.
    let mut stripper = StreamingStripper::new(pairs).with_scrub_patterns(scrub_regexes);
    let mut upstream_bytes = upstream_resp.bytes_stream();
    let log_request_id = request_id.clone();
    let log_agent_id = agent_id.clone();
    let log_injected_count = all_injected.len();

    // Cost tracking taps a bounded copy of the raw (pre-strip) response
    // bytes alongside the streamed delivery to the client — it never
    // delays or blocks that delivery. Capped so a huge response can't grow
    // this unboundedly; past the cap we still track the true total byte
    // count for the byte-length fallback estimate, just stop copying bytes.
    const COST_TAP_CAP: usize = 2_000_000;
    let mut cost_tap: Vec<u8> = Vec::new();
    let mut total_response_bytes: usize = 0;
    let is_sse = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false);
    let provider_slug = route.provider_slug.clone();
    let charge_credential = all_injected.first().cloned();
    let log_domain = domain.clone();
    let log_path = path.clone();
    let cost_credential_for_audit = all_injected.first().cloned();
    let state_for_audit = state.clone();
    let budget_tracker = state.budget_tracker.clone();

    let body_stream = async_stream::stream! {
        while let Some(chunk) = upstream_bytes.next().await {
            match chunk {
                Ok(bytes) => {
                    total_response_bytes += bytes.len();
                    if cost_tap.len() < COST_TAP_CAP {
                        let take = (COST_TAP_CAP - cost_tap.len()).min(bytes.len());
                        cost_tap.extend_from_slice(&bytes[..take]);
                    }

                    let out = stripper.process_chunk(&bytes);
                    if !out.is_empty() {
                        yield Ok::<axum::body::Bytes, std::io::Error>(axum::body::Bytes::from(out));
                    }
                }
                Err(e) => {
                    tracing::warn!(request_id = %log_request_id, error = %e, "upstream stream error");
                    yield Err(std::io::Error::other(e));
                    return;
                }
            }
        }

        let tail = stripper.flush();
        if !tail.is_empty() {
            yield Ok(axum::body::Bytes::from(tail));
        }

        let stripped_count = stripper.stripped_count();
        if stripped_count > 0 {
            tracing::info!(
                request_id = %log_request_id,
                agent = %log_agent_id,
                stripped_count = %stripped_count,
                credentials = ?stripper.stripped_credentials(),
                "credentials stripped from response"
            );
        }

        let scrubbed_count = stripper.scrubbed_count();
        if scrubbed_count > 0 {
            tracing::info!(
                request_id = %log_request_id,
                agent = %log_agent_id,
                scrubbed_count = %scrubbed_count,
                credentials = ?stripper.scrubbed_credentials(),
                "derived secrets redacted from response (scrub_patterns match)"
            );
        }

        // Estimate cost and record spend against the charged credential's
        // budget. Only for provider-prefixed routes (Host-header fallback
        // routing has no slug, hence no pricing basis) — see
        // route::RouteTarget::provider_slug.
        let cost_usd = if let Some(slug) = &provider_slug {
            let usage = if is_sse {
                cost::sse_usage_from_bytes(&cost_tap)
            } else {
                cost::extract_usage_from_json(&cost_tap)
            }
            .unwrap_or_else(|| cost::TokenUsage {
                input_tokens: cost::estimate_tokens_from_bytes(request_body_len),
                output_tokens: cost::estimate_tokens_from_bytes(total_response_bytes),
            });

            let model = cost::extract_model_from_json(&cost_tap)
                .or(request_model)
                .unwrap_or_else(|| "unknown".to_string());
            let usd = cost::estimate_cost_usd(slug, &model, usage);

            if let Some(cred) = &charge_credential {
                let mut bt = budget_tracker.lock().await;
                bt.record_spend(cred, &log_agent_id, usd);
            }

            tracing::info!(
                request_id = %log_request_id,
                agent = %log_agent_id,
                provider = %slug,
                model = %model,
                input_tokens = %usage.input_tokens,
                output_tokens = %usage.output_tokens,
                cost_usd = %format!("{usd:.6}"),
                "estimated request cost"
            );
            Some(usd)
        } else {
            None
        };

        tracing::info!(
            request_id = %log_request_id,
            agent = %log_agent_id,
            upstream_status = %resp_status.as_u16(),
            credentials_injected = %log_injected_count,
            credentials_stripped = %stripped_count,
            credentials_scrubbed = %scrubbed_count,
            "proxy request completed"
        );

        // Final dashboard audit entry: one record per successfully proxied
        // request. Errored requests are visible via tracing (and via the
        // loop/budget/rate_limit entries already recorded earlier in this
        // handler), but this single "request_completed" row is what the
        // dashboard's recent-activity table is built around.
        let mut entry = AuditEntry::new(&log_request_id, &log_agent_id, "request_completed")
            .request(&log_method, &log_domain, &log_path)
            .status(resp_status.as_u16());
        if let Some(c) = &cost_credential_for_audit {
            entry = entry.credential(c);
        }
        if let Some(usd) = cost_usd {
            entry = entry.cost(usd);
        }
        record_audit(&state_for_audit, entry);
    };

    response
        .body(Body::from_stream(body_stream))
        .map_err(|e| WardenError::Io(std::io::Error::other(e)))
}

fn error_response(err: WardenError) -> Response {
    let (status, body) = match &err {
        WardenError::Unauthorized {
            agent_id,
            credential,
        } => (
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "unauthorized",
                "agent": agent_id,
                "credential": credential,
            }),
        ),
        WardenError::DomainNotAllowed { domain, credential } => (
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "domain_not_allowed",
                "domain": domain,
                "credential": credential,
            }),
        ),
        WardenError::RateLimitExceeded {
            credential,
            agent_id,
            retry_after_seconds,
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({
                "error": "rate_limit_exceeded",
                "credential": credential,
                "agent": agent_id,
                "retry_after_seconds": retry_after_seconds,
            }),
        ),
        WardenError::BudgetExceeded {
            credential,
            agent_id,
            spent_usd,
            max_usd,
        } => (
            StatusCode::PAYMENT_REQUIRED,
            serde_json::json!({
                "error": "budget_exceeded",
                "credential": credential,
                "agent": agent_id,
                "spent_usd": spent_usd,
                "max_usd": max_usd,
            }),
        ),
        WardenError::LoopDetected {
            agent_id,
            repeat_count,
        } => (
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({
                "error": "loop_detected",
                "agent": agent_id,
                "repeat_count": repeat_count,
            }),
        ),
        _ => (
            StatusCode::BAD_GATEWAY,
            serde_json::json!({
                "error": "proxy_error",
                "message": err.to_string(),
            }),
        ),
    };

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap_or_default()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}
