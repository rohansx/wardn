use crate::vault::Vault;

/// Result of credential stripping from a response.
#[derive(Debug)]
pub struct StripResult {
    /// Number of credentials stripped.
    pub stripped_count: usize,
    /// Credential names that were stripped.
    pub stripped_credentials: Vec<String>,
}

/// A (real_value, placeholder, credential_name) replacement, sorted longest
/// `real_value` first so longer secrets are matched before any shorter
/// secret that happens to be a substring of them.
pub type ReplacementPairs = Vec<(String, String, String)>;

/// Build the set of (real_value, placeholder, credential_name) pairs to
/// strip from a response, for credentials that were injected into the
/// matching request. Only credentials with a value longer than 8 characters
/// are included, to avoid false-positive matches on short/common text.
///
/// This is computed once per request (while holding the vault lock) and
/// then reused for both header stripping and streaming body stripping —
/// neither of which need to touch the vault again.
pub fn build_replacement_pairs(
    agent_id: &str,
    injected_credentials: &[String],
    vault: &Vault,
) -> ReplacementPairs {
    let mut pairs: ReplacementPairs = Vec::new();
    for cred_name in injected_credentials {
        if let Some(cred_value) = vault.get(cred_name) {
            let value = cred_value.expose().to_string();
            // Only strip values > 8 chars to avoid false positives
            if value.len() > 8 {
                if let Some(placeholder) = vault.placeholder_for(cred_name, agent_id) {
                    pairs.push((value, placeholder, cred_name.clone()));
                }
            }
        }
    }

    // Sort longest first to prevent partial matches
    pairs.sort_by_key(|(value, ..)| std::cmp::Reverse(value.len()));
    pairs
}

/// Compile the scrub-pattern regexes configured on each injected
/// credential (see `CredentialConfig::scrub_patterns`), for the streaming
/// body scrubber. Bytes-based (`regex::bytes::Regex`) so it can run on raw
/// chunk data without requiring valid UTF-8 at chunk boundaries.
///
/// An invalid pattern is skipped with a warning rather than failing the
/// whole request — a typo'd regex in one credential's config shouldn't
/// break proxying for every request that touches it.
pub fn compile_scrub_regexes(
    injected_credentials: &[String],
    vault: &Vault,
) -> Vec<(regex::bytes::Regex, String)> {
    let mut regexes = Vec::new();
    for cred_name in injected_credentials {
        for pattern in vault.scrub_patterns(cred_name) {
            match regex::bytes::Regex::new(pattern) {
                Ok(re) => regexes.push((re, cred_name.clone())),
                Err(e) => {
                    tracing::warn!(
                        credential = %cred_name,
                        pattern = %pattern,
                        error = %e,
                        "invalid scrub_patterns regex, skipping"
                    );
                }
            }
        }
    }
    regexes
}

/// Apply already-built replacement pairs to a string, longest value first.
pub fn apply_pairs_str(input: &str, pairs: &ReplacementPairs) -> (String, StripResult) {
    let mut result = input.to_string();
    let mut stripped = Vec::new();

    for (real_value, placeholder, cred_name) in pairs {
        if result.contains(real_value.as_str()) {
            result = result.replace(real_value.as_str(), placeholder.as_str());
            stripped.push(cred_name.clone());
        }
    }

    (
        result,
        StripResult {
            stripped_count: stripped.len(),
            stripped_credentials: stripped,
        },
    )
}

/// Strip real credential values from response body, replacing with the
/// agent's placeholder tokens.
///
/// Only strips credential values that were actually injected in the request
/// (passed via `injected_credentials`) and are longer than 8 characters.
pub fn strip_body(
    body: &[u8],
    agent_id: &str,
    injected_credentials: &[String],
    vault: &Vault,
) -> (Vec<u8>, StripResult) {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            return (
                body.to_vec(),
                StripResult {
                    stripped_count: 0,
                    stripped_credentials: vec![],
                },
            )
        }
    };

    let pairs = build_replacement_pairs(agent_id, injected_credentials, vault);
    let (result, info) = apply_pairs_str(body_str, &pairs);
    (result.into_bytes(), info)
}

/// Strip real credential values from a header value.
pub fn strip_header_value(
    value: &str,
    agent_id: &str,
    injected_credentials: &[String],
    vault: &Vault,
) -> (String, usize) {
    let pairs = build_replacement_pairs(agent_id, injected_credentials, vault);
    let (result, info) = apply_pairs_str(value, &pairs);
    (result, info.stripped_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CredentialConfig;

    fn setup_vault() -> (Vault, String, String) {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "OPENAI_KEY",
                "sk-proj-real-key-123",
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

        let placeholder = vault
            .get_placeholder("OPENAI_KEY", "agent-1")
            .unwrap()
            .to_string();
        let cred_value = "sk-proj-real-key-123".to_string();
        (vault, placeholder, cred_value)
    }

    #[test]
    fn test_strip_echoed_key_from_body() {
        let (vault, placeholder, _) = setup_vault();
        let body = r#"{"error": "Invalid key: sk-proj-real-key-123", "code": 401}"#.to_string();

        let (result, info) = strip_body(
            body.as_bytes(),
            "agent-1",
            &["OPENAI_KEY".to_string()],
            &vault,
        );

        let result_str = String::from_utf8(result).unwrap();
        assert!(!result_str.contains("sk-proj-real-key-123"));
        assert!(result_str.contains(&placeholder));
        assert_eq!(info.stripped_count, 1);
    }

    #[test]
    fn test_strip_no_credentials_passthrough() {
        let (vault, _, _) = setup_vault();
        let body = r#"{"message": "success", "data": [1,2,3]}"#;

        let (result, info) = strip_body(
            body.as_bytes(),
            "agent-1",
            &["OPENAI_KEY".to_string()],
            &vault,
        );

        assert_eq!(String::from_utf8(result).unwrap(), body);
        assert_eq!(info.stripped_count, 0);
    }

    #[test]
    fn test_strip_uses_correct_agent_placeholder() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY",
                "secret-value-long-enough",
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

        let ph1 = vault.get_placeholder("KEY", "agent-1").unwrap().to_string();
        let ph2 = vault.get_placeholder("KEY", "agent-2").unwrap().to_string();

        let body = r#"Your key is: secret-value-long-enough"#;

        // Strip for agent-1 should use agent-1's placeholder
        let (result1, _) = strip_body(body.as_bytes(), "agent-1", &["KEY".to_string()], &vault);
        let r1 = String::from_utf8(result1).unwrap();
        assert!(r1.contains(&ph1));
        assert!(!r1.contains(&ph2));

        // Strip for agent-2 should use agent-2's placeholder
        let (result2, _) = strip_body(body.as_bytes(), "agent-2", &["KEY".to_string()], &vault);
        let r2 = String::from_utf8(result2).unwrap();
        assert!(r2.contains(&ph2));
        assert!(!r2.contains(&ph1));
    }

    #[test]
    fn test_strip_skips_short_values() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "SHORT",
                "abc", // <= 8 chars, should NOT be stripped
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
        vault.get_placeholder("SHORT", "agent").unwrap();

        let body = r#"value is abc here"#;
        let (result, info) = strip_body(body.as_bytes(), "agent", &["SHORT".to_string()], &vault);

        // "abc" should NOT be stripped (too short, false positive risk)
        assert_eq!(String::from_utf8(result).unwrap(), body);
        assert_eq!(info.stripped_count, 0);
    }

    #[test]
    fn test_strip_header_value() {
        let (vault, placeholder, _) = setup_vault();
        let header = "Bearer sk-proj-real-key-123";

        let (result, count) =
            strip_header_value(header, "agent-1", &["OPENAI_KEY".to_string()], &vault);

        assert!(!result.contains("sk-proj-real-key-123"));
        assert!(result.contains(&placeholder));
        assert_eq!(count, 1);
    }

    #[test]
    fn test_strip_only_injected_credentials() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY_A",
                "secret-value-a-long",
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
        vault
            .set_with_config(
                "KEY_B",
                "secret-value-b-long",
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
        vault.get_placeholder("KEY_A", "agent").unwrap();
        vault.get_placeholder("KEY_B", "agent").unwrap();

        // Both values appear in body, but only KEY_A was injected
        let body = r#"a=secret-value-a-long b=secret-value-b-long"#;
        let (result, info) = strip_body(
            body.as_bytes(),
            "agent",
            &["KEY_A".to_string()], // only KEY_A injected
            &vault,
        );

        let r = String::from_utf8(result).unwrap();
        assert!(!r.contains("secret-value-a-long")); // stripped
        assert!(r.contains("secret-value-b-long")); // NOT stripped (wasn't injected)
        assert_eq!(info.stripped_count, 1);
    }
}
