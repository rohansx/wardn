use std::path::Path;

use serde::Serialize;

/// A credential found in plaintext on disk.
#[derive(Debug, Clone, Serialize)]
pub struct FoundCredential {
    pub name: String,
    pub value_preview: String, // first 8 chars + "..."
    /// The full real value — deliberately NOT serialized (`#[serde(skip)]`).
    /// `to_terminal_string`/JSON export must only ever show `value_preview`;
    /// this field exists so `migrate` (non-dry-run) can actually store the
    /// real credential in the vault instead of a placeholder marker.
    #[serde(skip)]
    pub value: String,
    pub source_file: String,
    pub category: CredentialCategory,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub enum CredentialCategory {
    Anthropic,
    OpenAI,
    GitHub,
    Slack,
    Telegram,
    Stripe,
    AWS,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Known credential patterns to scan for.
struct Pattern {
    name: &'static str,
    prefix: &'static str,
    category: CredentialCategory,
    severity: Severity,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        name: "ANTHROPIC_API_KEY",
        prefix: "sk-ant-",
        category: CredentialCategory::Anthropic,
        severity: Severity::Critical,
    },
    Pattern {
        name: "OPENAI_API_KEY",
        prefix: "sk-proj-",
        category: CredentialCategory::OpenAI,
        severity: Severity::Critical,
    },
    Pattern {
        name: "OPENAI_API_KEY",
        prefix: "sk-",
        category: CredentialCategory::OpenAI,
        severity: Severity::Critical,
    },
    Pattern {
        name: "GITHUB_TOKEN",
        prefix: "ghp_",
        category: CredentialCategory::GitHub,
        severity: Severity::High,
    },
    Pattern {
        name: "GITHUB_TOKEN",
        prefix: "gho_",
        category: CredentialCategory::GitHub,
        severity: Severity::High,
    },
    Pattern {
        name: "SLACK_TOKEN",
        prefix: "xoxb-",
        category: CredentialCategory::Slack,
        severity: Severity::High,
    },
    Pattern {
        name: "SLACK_TOKEN",
        prefix: "xoxp-",
        category: CredentialCategory::Slack,
        severity: Severity::High,
    },
    Pattern {
        name: "TELEGRAM_TOKEN",
        prefix: "bot",
        category: CredentialCategory::Telegram,
        severity: Severity::Medium,
    },
    Pattern {
        name: "STRIPE_KEY",
        prefix: "sk_live_",
        category: CredentialCategory::Stripe,
        severity: Severity::Critical,
    },
    Pattern {
        name: "STRIPE_KEY",
        prefix: "sk_test_",
        category: CredentialCategory::Stripe,
        severity: Severity::Medium,
    },
    Pattern {
        name: "AWS_ACCESS_KEY",
        prefix: "AKIA",
        category: CredentialCategory::AWS,
        severity: Severity::Critical,
    },
];

/// Scan a file's content for plaintext credentials.
pub fn scan_content(content: &str, source_file: &str) -> Vec<FoundCredential> {
    let mut found = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Check for key=value patterns
        if let Some((key, value)) = parse_key_value(trimmed) {
            for pattern in PATTERNS {
                if value.starts_with(pattern.prefix) && value.len() > pattern.prefix.len() + 4 {
                    let preview = if value.len() > 12 {
                        format!("{}...{}", &value[..8], &value[value.len() - 4..])
                    } else {
                        format!("{}...", &value[..value.len().min(8)])
                    };
                    found.push(FoundCredential {
                        name: key.to_string(),
                        value_preview: preview,
                        value: value.to_string(),
                        source_file: source_file.to_string(),
                        category: pattern.category.clone(),
                        severity: pattern.severity,
                    });
                    break;
                }
            }
        }

        // Check for bare credential values (not in key=value format)
        for pattern in PATTERNS {
            if trimmed.contains(pattern.prefix) {
                // Find the token within the line
                if let Some(start) = trimmed.find(pattern.prefix) {
                    let rest = &trimmed[start..];
                    let end = rest
                        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
                        .unwrap_or(rest.len());
                    let value = &rest[..end];

                    if value.len() > pattern.prefix.len() + 4 {
                        // Avoid duplicates from key=value parsing above
                        let already_found = found.iter().any(|f| {
                            f.source_file == source_file
                                && value.starts_with(
                                    &f.value_preview
                                        [..f.value_preview.len().min(8).min(value.len())],
                                )
                        });
                        if !already_found {
                            let preview = if value.len() > 12 {
                                format!("{}...{}", &value[..8], &value[value.len() - 4..])
                            } else {
                                format!("{}...", &value[..value.len().min(8)])
                            };
                            found.push(FoundCredential {
                                name: pattern.name.to_string(),
                                value_preview: preview,
                                value: value.to_string(),
                                source_file: source_file.to_string(),
                                category: pattern.category.clone(),
                                severity: pattern.severity,
                            });
                        }
                    }
                }
            }
        }
    }

    found
}

/// Scan a directory recursively for plaintext credentials.
pub fn scan_directory(dir: &Path) -> Vec<FoundCredential> {
    let mut results = Vec::new();

    if !dir.exists() || !dir.is_dir() {
        return results;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            // Skip common non-relevant dirs
            let name = path.file_name().unwrap_or_default().to_str().unwrap_or("");
            if name == "node_modules" || name == ".git" || name == "target" {
                continue;
            }
            results.extend(scan_directory(&path));
        } else if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Only scan text config files
            let scannable = matches!(
                ext,
                "toml" | "json" | "yaml" | "yml" | "env" | "conf" | "cfg" | "ini" | "txt"
            ) || matches!(
                name,
                ".env" | ".env.local" | ".env.production" | "credentials" | "config"
            );

            if !scannable {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&path) {
                let file_str = path.display().to_string();
                results.extend(scan_content(&content, &file_str));
            }
        }
    }

    results
}

fn parse_key_value(line: &str) -> Option<(&str, &str)> {
    // Handle: KEY=VALUE, KEY = VALUE, "key": "value"
    if let Some(eq_pos) = line.find('=') {
        let key = line[..eq_pos].trim().trim_matches('"').trim_matches('\'');
        let value = line[eq_pos + 1..]
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        if !key.is_empty() && !value.is_empty() {
            return Some((key, value));
        }
    }

    // JSON style: "key": "value"
    if line.contains(':') {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let key = parts[0]
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches(',');
            let value = parts[1]
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .trim_matches(',');
            if !key.is_empty() && !value.is_empty() {
                return Some((key, value));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_env_file() {
        let content = r#"
OPENAI_API_KEY=sk-proj-abc123def456ghi789
ANTHROPIC_API_KEY=sk-ant-secret-key-12345
DATABASE_URL=postgres://localhost/mydb
"#;
        let results = scan_content(content, ".env");
        assert!(results.len() >= 2);

        let openai = results.iter().find(|r| r.name == "OPENAI_API_KEY");
        assert!(openai.is_some());
        assert_eq!(openai.unwrap().severity, Severity::Critical);

        let anthropic = results.iter().find(|r| r.name == "ANTHROPIC_API_KEY");
        assert!(anthropic.is_some());
    }

    #[test]
    fn test_scan_captures_real_value_not_just_preview() {
        let content = "OPENAI_API_KEY=sk-proj-abc123def456ghi789\n";
        let results = scan_content(content, ".env");
        let openai = results.iter().find(|r| r.name == "OPENAI_API_KEY").unwrap();

        assert_eq!(openai.value, "sk-proj-abc123def456ghi789");
        // The preview is still a truncated, distinct representation.
        assert_ne!(openai.value, openai.value_preview);
        assert!(openai.value_preview.contains("..."));
    }

    #[test]
    fn test_found_credential_serialization_never_includes_value() {
        let content = "OPENAI_API_KEY=sk-proj-abc123def456ghi789\n";
        let results = scan_content(content, ".env");
        let json = serde_json::to_string(&results[0]).unwrap();
        assert!(!json.contains("sk-proj-abc123def456ghi789"));
        assert!(json.contains("value_preview"));
    }

    #[test]
    fn test_scan_json_config() {
        let content = r#"
{
    "api_key": "sk-proj-my-secret-openai-key-12345",
    "model": "gpt-4"
}
"#;
        let results = scan_content(content, "config.json");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_scan_toml_config() {
        let content = r#"
[settings]
api_key = "sk-ant-my-anthropic-key-12345"
timeout = 30
"#;
        let results = scan_content(content, "config.toml");
        assert!(!results.is_empty());
        assert_eq!(results[0].severity, Severity::Critical);
    }

    #[test]
    fn test_scan_github_token() {
        let content = "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678\n";
        let results = scan_content(content, ".env");
        assert!(!results.is_empty());
        assert_eq!(results[0].severity, Severity::High);
    }

    #[test]
    fn test_scan_aws_key() {
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
        let results = scan_content(content, ".env");
        assert!(!results.is_empty());
        assert_eq!(results[0].severity, Severity::Critical);
    }

    #[test]
    fn test_scan_skips_comments() {
        let content = "# OPENAI_API_KEY=sk-proj-abc123def456ghi789\n";
        let results = scan_content(content, ".env");
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_skips_short_values() {
        let content = "KEY=sk-\n"; // too short to be a real key
        let results = scan_content(content, ".env");
        assert!(results.is_empty());
    }

    #[test]
    fn test_value_preview_truncated() {
        let content = "KEY=sk-proj-this-is-a-very-long-api-key-value-12345\n";
        let results = scan_content(content, ".env");
        assert!(!results.is_empty());
        let preview = &results[0].value_preview;
        // Should be truncated, not the full value
        assert!(preview.contains("..."));
        assert!(preview.len() < 30);
    }

    #[test]
    fn test_scan_empty_content() {
        let results = scan_content("", ".env");
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_nonexistent_directory() {
        let results = scan_directory(Path::new("/tmp/nonexistent-dir-wardn-test"));
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_directory_with_env_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        std::fs::write(&env_path, "OPENAI_KEY=sk-proj-abc123def456ghi789\n").unwrap();

        let results = scan_directory(dir.path());
        assert!(!results.is_empty());
    }

    #[test]
    fn test_stripe_live_vs_test() {
        let content =
            "STRIPE_LIVE=sk_live_abcdef1234567890\nSTRIPE_TEST=sk_test_abcdef1234567890\n";
        let results = scan_content(content, ".env");
        assert!(results.len() >= 2);

        let live = results
            .iter()
            .find(|r| r.value_preview.starts_with("sk_live_"));
        let test = results
            .iter()
            .find(|r| r.value_preview.starts_with("sk_test_"));
        assert!(live.is_some());
        assert!(test.is_some());
        assert_eq!(live.unwrap().severity, Severity::Critical);
        assert_eq!(test.unwrap().severity, Severity::Medium);
    }
}
