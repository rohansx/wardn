use serde::Deserialize;

use crate::config::OAuthConfig;
use crate::WardenError;

/// Refresh this many seconds before actual expiry, so a request already in
/// flight doesn't race against the token expiring mid-call.
const REFRESH_MARGIN_SECS: i64 = 60;

/// Whether an OAuth-backed credential's access token should be refreshed
/// before use, given the current unix time. Pure/time-injectable so it's
/// directly testable without waiting on a real clock.
pub fn needs_refresh(config: &OAuthConfig, now_unix: i64) -> bool {
    match config.expires_at {
        Some(expires_at) => now_unix >= expires_at - REFRESH_MARGIN_SECS,
        // No known expiry — treat as expired so we refresh on first use
        // rather than ever assume a token with unknown freshness is fine.
        None => true,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RefreshedTokens {
    pub access_token: String,
    /// `None` when the provider didn't rotate the refresh token — the
    /// existing one stays valid.
    pub refresh_token: Option<String>,
    /// Unix timestamp the new access token expires at, if the provider
    /// reported `expires_in`.
    pub expires_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// Perform an OAuth2 refresh_token grant (RFC 6749 §6) against
/// `config.token_url`.
///
/// Purely does the HTTP exchange — it does NOT touch the vault. Callers
/// persist the result via `Vault::update_oauth_tokens`. `now_unix` is
/// injected (not read from the system clock here) so the expiry
/// computation is testable.
pub async fn refresh_access_token(
    client: &reqwest::Client,
    credential_name: &str,
    config: &OAuthConfig,
    now_unix: i64,
) -> crate::Result<RefreshedTokens> {
    let mut params = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", config.refresh_token.as_str()),
        ("client_id", config.client_id.as_str()),
    ];
    if let Some(secret) = &config.client_secret {
        params.push(("client_secret", secret.as_str()));
    }

    let resp = client
        .post(&config.token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| WardenError::OAuthRefreshFailed {
            credential: credential_name.to_string(),
            reason: format!("request failed: {e}"),
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(WardenError::OAuthRefreshFailed {
            credential: credential_name.to_string(),
            reason: format!("upstream returned {status}: {body}"),
        });
    }

    let parsed: TokenResponse = resp
        .json()
        .await
        .map_err(|e| WardenError::OAuthRefreshFailed {
            credential: credential_name.to_string(),
            reason: format!("could not parse token response: {e}"),
        })?;

    let expires_at = parsed.expires_in.map(|secs| now_unix + secs);

    Ok(RefreshedTokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(token_url: &str) -> OAuthConfig {
        OAuthConfig {
            token_url: token_url.to_string(),
            client_id: "client-123".to_string(),
            client_secret: Some("secret-abc".to_string()),
            refresh_token: "old-refresh-token".to_string(),
            expires_at: None,
        }
    }

    #[test]
    fn test_needs_refresh_when_past_expiry() {
        let config = OAuthConfig {
            expires_at: Some(1000),
            ..config("http://example.com")
        };
        assert!(needs_refresh(&config, 1000));
        assert!(needs_refresh(&config, 2000));
    }

    #[test]
    fn test_needs_refresh_within_safety_margin() {
        let config = OAuthConfig {
            expires_at: Some(1000),
            ..config("http://example.com")
        };
        // 950 is within the 60s margin before 1000 — must refresh already.
        assert!(needs_refresh(&config, 950));
    }

    #[test]
    fn test_does_not_need_refresh_when_comfortably_valid() {
        let config = OAuthConfig {
            expires_at: Some(10_000),
            ..config("http://example.com")
        };
        assert!(!needs_refresh(&config, 1_000));
    }

    #[test]
    fn test_needs_refresh_when_expiry_unknown() {
        let config = OAuthConfig {
            expires_at: None,
            ..config("http://example.com")
        };
        assert!(needs_refresh(&config, 1));
    }

    #[tokio::test]
    async fn test_refresh_access_token_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=old-refresh-token"))
            .and(body_string_contains("client_id=client-123"))
            .and(body_string_contains("client_secret=secret-abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token",
                "refresh_token": "new-refresh-token",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let cfg = config(&format!("{}/token", server.uri()));
        let result = refresh_access_token(&client, "MY_CRED", &cfg, 1_000_000)
            .await
            .unwrap();

        assert_eq!(result.access_token, "new-access-token");
        assert_eq!(result.refresh_token, Some("new-refresh-token".to_string()));
        assert_eq!(result.expires_at, Some(1_000_000 + 3600));
    }

    #[tokio::test]
    async fn test_refresh_access_token_without_client_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token"
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let cfg = OAuthConfig {
            client_secret: None,
            ..config(&format!("{}/token", server.uri()))
        };
        let result = refresh_access_token(&client, "MY_CRED", &cfg, 0)
            .await
            .unwrap();

        assert_eq!(result.access_token, "new-access-token");
        assert_eq!(result.refresh_token, None);
        assert_eq!(result.expires_at, None); // provider didn't send expires_in
    }

    #[tokio::test]
    async fn test_refresh_access_token_provider_error_returns_oauth_refresh_failed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let cfg = config(&format!("{}/token", server.uri()));
        let result = refresh_access_token(&client, "MY_CRED", &cfg, 0).await;

        match result {
            Err(WardenError::OAuthRefreshFailed { credential, reason }) => {
                assert_eq!(credential, "MY_CRED");
                assert!(reason.contains("400"));
            }
            other => panic!("expected OAuthRefreshFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_refresh_access_token_malformed_response_fails() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let cfg = config(&format!("{}/token", server.uri()));
        let result = refresh_access_token(&client, "MY_CRED", &cfg, 0).await;
        assert!(matches!(
            result,
            Err(WardenError::OAuthRefreshFailed { .. })
        ));
    }
}
