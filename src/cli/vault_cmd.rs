use std::path::Path;

use anyhow::{bail, Context, Result};

use wardn::config::CredentialConfig;
use wardn::Vault;

use super::VaultCommands;

/// Read passphrase from WARDN_PASSPHRASE env var, then the OS keychain,
/// then prompt interactively.
fn read_passphrase(vault_path: &Path, prompt: &str) -> Result<String> {
    if let Ok(pass) = std::env::var("WARDN_PASSPHRASE") {
        tracing::warn!(
            "using passphrase from WARDN_PASSPHRASE env var — not recommended for production"
        );
        return Ok(pass);
    }
    if let Some(pass) = wardn::vault::keyring_store::retrieve_passphrase(vault_path) {
        return Ok(pass);
    }
    rpassword::prompt_password(prompt).context("failed to read passphrase")
}

/// Read a secret value from WARDN_VALUE env var or prompt interactively.
fn read_value(prompt: &str) -> Result<String> {
    if let Ok(val) = std::env::var("WARDN_VALUE") {
        return Ok(val);
    }
    rpassword::prompt_password(prompt).context("failed to read value")
}

/// Parse comma-separated domain input into a clean list. Pure/testable —
/// the actual stdin read happens in `prompt_for_domains`.
fn parse_domain_input(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Resolve which domains to scope a new credential to.
///
/// If `--domain` was passed, use it as-is. Otherwise: in non-interactive/
/// scripted use (WARDN_VALUE set — the same signal `read_value` already
/// uses), default to unrestricted with a loud warning, since there's no
/// one to prompt. Interactively, ask — so "any domain" is a conscious
/// choice, not a silent default. An empty list means "any domain" (see
/// `Vault::is_domain_allowed`).
fn resolve_domains(key: &str, domains: &[String]) -> Result<Vec<String>> {
    if !domains.is_empty() {
        return Ok(domains.to_vec());
    }

    if std::env::var("WARDN_VALUE").is_ok() {
        eprintln!(
            "warning: no --domain given for {key} — it will be usable against ANY domain \
             through the proxy. Pass --domain to scope it."
        );
        return Ok(Vec::new());
    }

    eprintln!(
        "No --domain specified for {key}. A credential with no domain restriction can be \
         used against ANY host through the wardn proxy — if a placeholder leaks, that turns \
         into a way to exfiltrate the real key to an attacker's server."
    );
    print!("Enter allowed domains (comma-separated), or press Enter to allow ANY domain: ");
    std::io::Write::flush(&mut std::io::stdout()).ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("failed to read domain input")?;

    Ok(parse_domain_input(&input))
}

pub fn run(cmd: &VaultCommands, vault_path: &Path) -> Result<()> {
    match cmd {
        VaultCommands::Create => {
            if vault_path.exists() {
                bail!("vault already exists at {}", vault_path.display());
            }

            if let Some(parent) = vault_path.parent() {
                std::fs::create_dir_all(parent).context("failed to create vault directory")?;
            }

            let passphrase = read_passphrase(vault_path, "Passphrase: ")?;
            let confirm = read_passphrase(vault_path, "Confirm passphrase: ")?;

            if passphrase != confirm {
                bail!("passphrases do not match");
            }

            if passphrase.is_empty() {
                bail!("passphrase cannot be empty");
            }

            Vault::create(vault_path, &passphrase)?;
            println!("vault created at {}", vault_path.display());
        }

        VaultCommands::Set { key, domains } => {
            let passphrase = read_passphrase(vault_path, "Passphrase: ")?;
            let mut vault = Vault::open(vault_path, &passphrase)?;

            let value = read_value(&format!("Value for {key}: "))?;
            if value.is_empty() {
                bail!("value cannot be empty");
            }

            let allowed_domains = resolve_domains(key, domains)?;
            vault.set_with_config(
                key,
                &value,
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    allowed_agents: Vec::new(),
                    allowed_domains: allowed_domains.clone(),
                    rate_limit: None,
                    budget: None,
                    oauth: None,
                },
            )?;

            if allowed_domains.is_empty() {
                println!("stored {key} (unrestricted — any domain)");
            } else {
                println!(
                    "stored {key} (restricted to: {})",
                    allowed_domains.join(", ")
                );
            }
        }

        VaultCommands::Get { key, agent } => {
            let passphrase = read_passphrase(vault_path, "Passphrase: ")?;
            let mut vault = Vault::open(vault_path, &passphrase)?;

            let placeholder = vault.get_placeholder(key, agent)?;
            println!("{}", placeholder.as_str());
        }

        VaultCommands::List => {
            let passphrase = read_passphrase(vault_path, "Passphrase: ")?;
            let vault = Vault::open(vault_path, &passphrase)?;

            let creds = vault.list();
            if creds.is_empty() {
                println!("vault is empty");
                return Ok(());
            }

            println!(
                "{:<24} {:<20} {:<20} {:<10} CREATED",
                "NAME", "AGENTS", "DOMAINS", "RATE LIMIT"
            );
            println!("{}", "-".repeat(90));

            for info in &creds {
                let agents = if info.allowed_agents.is_empty() {
                    "*".to_string()
                } else {
                    info.allowed_agents.join(", ")
                };
                let domains = if info.allowed_domains.is_empty() {
                    "*".to_string()
                } else {
                    info.allowed_domains.join(", ")
                };
                let rl = if info.has_rate_limit { "yes" } else { "no" };
                let created = &info.created_at[..10]; // date only

                println!(
                    "{:<24} {:<20} {:<20} {:<10} {}",
                    info.name, agents, domains, rl, created
                );
            }
        }

        VaultCommands::Rotate { key } => {
            let passphrase = read_passphrase(vault_path, "Passphrase: ")?;
            let mut vault = Vault::open(vault_path, &passphrase)?;

            let new_value = read_value(&format!("New value for {key}: "))?;
            if new_value.is_empty() {
                bail!("value cannot be empty");
            }

            vault.rotate(key, &new_value)?;
            println!("rotated {key} — existing placeholders unchanged");
        }

        VaultCommands::Remove { key } => {
            let passphrase = read_passphrase(vault_path, "Passphrase: ")?;
            let mut vault = Vault::open(vault_path, &passphrase)?;

            vault.remove(key)?;
            println!("removed {key}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_input_splits_and_trims() {
        let domains = parse_domain_input(" api.openai.com, api.example.com ,,other.com\n");
        assert_eq!(
            domains,
            vec![
                "api.openai.com".to_string(),
                "api.example.com".to_string(),
                "other.com".to_string(),
            ]
        );
    }

    #[test]
    fn test_parse_domain_input_empty_returns_empty() {
        assert!(parse_domain_input("\n").is_empty());
        assert!(parse_domain_input("").is_empty());
        assert!(parse_domain_input("   ").is_empty());
    }

    #[test]
    fn test_resolve_domains_uses_explicit_flag_without_prompting() {
        // With --domain values already present, resolve_domains must return
        // them directly without touching stdin/env at all.
        let domains = resolve_domains("KEY", &["api.example.com".to_string()]).unwrap();
        assert_eq!(domains, vec!["api.example.com".to_string()]);
    }
}
