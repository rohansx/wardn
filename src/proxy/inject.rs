use crate::vault::Vault;
use crate::WardenError;

/// Result of credential injection into a request.
#[derive(Debug)]
pub struct InjectionResult {
    /// Credential names that were injected.
    pub injected: Vec<String>,
}

const PLACEHOLDER_PREFIX: &str = "wdn_placeholder_";
const PLACEHOLDER_HEX_LEN: usize = 16;

/// A candidate placeholder token found while scanning text.
struct PlaceholderMatch {
    /// Byte offset where the prefix starts.
    start: usize,
    /// Byte offset to resume scanning from after this match.
    resume_from: usize,
    /// The full token text, only set when exactly `PLACEHOLDER_HEX_LEN`
    /// valid hex characters followed the prefix.
    token: Option<String>,
}

/// Find the next placeholder-shaped span starting at or after `from`.
///
/// Unlike a fixed-width slice, this only consumes as many hex characters as
/// are actually present (up to 16). A truncated or malformed candidate does
/// not abort the scan — it just resumes right after the prefix, so a
/// well-formed token later in the same buffer is still found.
fn find_next_placeholder(haystack: &str, from: usize) -> Option<PlaceholderMatch> {
    let rel_start = haystack[from..].find(PLACEHOLDER_PREFIX)?;
    let start = from + rel_start;
    let hex_start = start + PLACEHOLDER_PREFIX.len();

    let hex_len = haystack[hex_start..]
        .bytes()
        .take(PLACEHOLDER_HEX_LEN)
        .take_while(|b| b.is_ascii_hexdigit())
        .count();

    if hex_len == PLACEHOLDER_HEX_LEN {
        let end = hex_start + PLACEHOLDER_HEX_LEN;
        Some(PlaceholderMatch {
            start,
            resume_from: end,
            token: Some(haystack[start..end].to_string()),
        })
    } else {
        // Malformed/truncated candidate — resume right after the prefix so
        // we don't skip over a real token embedded further in this span.
        Some(PlaceholderMatch {
            start,
            resume_from: hex_start,
            token: None,
        })
    }
}

/// Scan a header value for placeholder tokens and replace with real credentials.
/// Returns the replaced value and list of injected credential names.
///
/// Only injects a placeholder that was actually issued to `agent_id` — see
/// `Vault::resolve_placeholder_for_agent`. A placeholder presented under a
/// different claimed agent (e.g. stolen and replayed with a spoofed
/// `x-warden-agent` header) is treated as unknown, same as any other
/// unrecognized token.
pub fn inject_header_value(
    value: &str,
    agent_id: &str,
    domain: &str,
    vault: &Vault,
) -> crate::Result<(String, Vec<String>)> {
    let mut result = value.to_string();
    let mut injected = Vec::new();

    let mut search_from = 0;
    while let Some(m) = find_next_placeholder(&result, search_from) {
        let Some(token) = m.token else {
            search_from = m.resume_from;
            continue;
        };

        if let Some((cred_name, cred_value)) = vault.resolve_placeholder_for_agent(&token, agent_id)
        {
            // Check domain authorization
            if !vault.is_domain_allowed(cred_name, domain) {
                return Err(WardenError::DomainNotAllowed {
                    domain: domain.to_string(),
                    credential: cred_name.to_string(),
                });
            }

            let real_value = cred_value.expose().to_string();
            result = format!(
                "{}{}{}",
                &result[..m.start],
                real_value,
                &result[m.resume_from..]
            );
            injected.push(cred_name.to_string());
            // Advance past the injected value
            search_from = m.start + real_value.len();
        } else {
            // Unknown placeholder — skip past it
            search_from = m.resume_from;
        }
    }

    Ok((result, injected))
}

/// Scan a body for placeholder tokens and replace with real credentials.
pub fn inject_body(
    body: &[u8],
    agent_id: &str,
    domain: &str,
    vault: &Vault,
) -> crate::Result<(Vec<u8>, Vec<String>)> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return Ok((body.to_vec(), vec![])), // binary body, skip
    };

    let (replaced, injected) = inject_header_value(body_str, agent_id, domain, vault)?;
    Ok((replaced.into_bytes(), injected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CredentialConfig;

    fn setup_vault() -> (Vault, String) {
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

        let placeholder = vault.get_placeholder("OPENAI_KEY", "researcher").unwrap();
        (vault, placeholder.to_string())
    }

    #[test]
    fn test_inject_bearer_header() {
        let (vault, ph) = setup_vault();
        let header = format!("Bearer {ph}");

        let (result, injected) =
            inject_header_value(&header, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, "Bearer sk-proj-real-key-123");
        assert_eq!(injected, vec!["OPENAI_KEY"]);
    }

    #[test]
    fn test_inject_body_json() {
        let (vault, ph) = setup_vault();
        let body = format!(r#"{{"api_key": "{ph}", "prompt": "hello"}}"#);

        let (result, injected) =
            inject_body(body.as_bytes(), "researcher", "api.openai.com", &vault).unwrap();

        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.contains("sk-proj-real-key-123"));
        assert!(!result_str.contains("wdn_placeholder_"));
        assert_eq!(injected, vec!["OPENAI_KEY"]);
    }

    #[test]
    fn test_inject_stolen_placeholder_under_spoofed_agent_is_not_injected() {
        // setup_vault() issues the placeholder to "researcher". A process
        // presenting that same token but claiming to be a different agent
        // (e.g. a spoofed x-warden-agent header after the token leaked)
        // must NOT get the real key — same treatment as an unknown token.
        let (vault, ph) = setup_vault();
        let header = format!("Bearer {ph}");

        let (result, injected) =
            inject_header_value(&header, "attacker", "api.openai.com", &vault).unwrap();

        assert_eq!(
            result, header,
            "real key must not be injected for a mismatched agent claim"
        );
        assert!(injected.is_empty());
    }

    #[test]
    fn test_inject_wrong_domain_fails() {
        let (vault, ph) = setup_vault();
        let header = format!("Bearer {ph}");

        let result = inject_header_value(&header, "researcher", "evil.com", &vault);
        assert!(matches!(result, Err(WardenError::DomainNotAllowed { .. })));
    }

    #[test]
    fn test_inject_no_placeholders_passthrough() {
        let (vault, _) = setup_vault();
        let header = "Bearer sk-some-other-key";

        let (result, injected) =
            inject_header_value(header, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, "Bearer sk-some-other-key");
        assert!(injected.is_empty());
    }

    #[test]
    fn test_inject_unknown_placeholder_passthrough() {
        let (vault, _) = setup_vault();
        let header = "Bearer wdn_placeholder_0000000000000000";

        let (result, injected) =
            inject_header_value(header, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, "Bearer wdn_placeholder_0000000000000000");
        assert!(injected.is_empty());
    }

    #[test]
    fn test_inject_multiple_placeholders() {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                "KEY_A",
                "secret-a",
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
                "secret-b",
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

        let ph_a = vault.get_placeholder("KEY_A", "agent").unwrap().to_string();
        let ph_b = vault.get_placeholder("KEY_B", "agent").unwrap().to_string();

        let body = format!(r#"{{"a": "{ph_a}", "b": "{ph_b}"}}"#);
        let (result, injected) = inject_body(body.as_bytes(), "agent", "any.com", &vault).unwrap();

        let result_str = String::from_utf8(result).unwrap();
        assert!(result_str.contains("secret-a"));
        assert!(result_str.contains("secret-b"));
        assert!(!result_str.contains("wdn_placeholder_"));
        assert_eq!(injected.len(), 2);
    }

    #[test]
    fn test_inject_binary_body_passthrough() {
        let (vault, _) = setup_vault();
        let binary = vec![0xFF, 0xFE, 0x00, 0x01];

        let (result, injected) =
            inject_body(&binary, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, binary);
        assert!(injected.is_empty());
    }

    #[test]
    fn test_inject_truncated_token_does_not_abort_scan() {
        // A malformed/truncated "wdn_placeholder_" candidate earlier in the
        // buffer must not stop the scanner from finding a real, well-formed
        // token later in the same buffer.
        let (vault, ph) = setup_vault();
        let body = format!("wdn_placeholder_abc garbage then {ph} at the end");

        let (result, injected) =
            inject_header_value(&body, "researcher", "api.openai.com", &vault).unwrap();

        assert!(result.contains("sk-proj-real-key-123"));
        assert_eq!(injected, vec!["OPENAI_KEY"]);
    }

    #[test]
    fn test_inject_token_at_exact_buffer_end() {
        let (vault, ph) = setup_vault();
        let body = format!("Bearer {ph}");

        let (result, injected) =
            inject_header_value(&body, "researcher", "api.openai.com", &vault).unwrap();

        assert_eq!(result, "Bearer sk-proj-real-key-123");
        assert_eq!(injected, vec!["OPENAI_KEY"]);
    }

    #[test]
    fn test_inject_non_hex_after_prefix_does_not_swallow_next_token() {
        // Garbage right after the prefix (not 16 valid hex chars) should not
        // cause the scanner to jump past a legitimate token that follows.
        let (vault, ph) = setup_vault();
        let body = format!("wdn_placeholder_not-hex-at-all {ph}");

        let (result, injected) =
            inject_header_value(&body, "researcher", "api.openai.com", &vault).unwrap();

        assert!(result.contains("sk-proj-real-key-123"));
        assert_eq!(injected, vec!["OPENAI_KEY"]);
    }
}
