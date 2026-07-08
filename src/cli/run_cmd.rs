use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};

use wardn::config::{BudgetConfig, BudgetMode, BudgetWindow, WardenConfig};
use wardn::Vault;

use super::RunArgs;

/// A known provider's env-var conventions. `credential_names` lists the
/// vault credential names that count as "this provider is configured";
/// whichever is found first wins.
struct ProviderMapping {
    slug: &'static str,
    credential_names: &'static [&'static str],
    base_url_env: &'static str,
    auth_env_vars: &'static [&'static str],
}

/// Built-in mappings for the two upstreams wardn ships with by default
/// (`WardenConfig::default()` — see `config::default_upstreams`). Custom
/// upstream slugs added via `wardn.toml` fall back to the `{SLUG}_KEY` /
/// `{SLUG}_BASE_URL` / `{SLUG}_API_KEY` convention in `resolve_env_for_agent`.
const KNOWN_PROVIDERS: &[ProviderMapping] = &[
    ProviderMapping {
        slug: "anthropic",
        credential_names: &["ANTHROPIC_KEY", "ANTHROPIC_API_KEY"],
        base_url_env: "ANTHROPIC_BASE_URL",
        // Claude Code and the Anthropic SDKs accept either; set both so
        // whichever the target tool reads for a custom base URL works.
        auth_env_vars: &["ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"],
    },
    ProviderMapping {
        slug: "openai",
        credential_names: &["OPENAI_KEY", "OPENAI_API_KEY"],
        base_url_env: "OPENAI_BASE_URL",
        auth_env_vars: &["OPENAI_API_KEY"],
    },
];

pub async fn run(args: &RunArgs, vault_path: &Path, config_path: Option<&Path>) -> Result<()> {
    let (cmd, cmd_args) = args
        .command
        .split_first()
        .context("no command given — usage: wardn run -- <command> [args...]")?;

    let passphrase = resolve_passphrase(vault_path)?;
    let mut vault = Vault::open(vault_path, &passphrase).context("failed to open vault")?;

    let warden_config = match config_path {
        Some(p) => WardenConfig::load(p)?,
        None => WardenConfig::default(),
    };

    ensure_daemon_running(&args.host, args.port, vault_path, config_path, &passphrase).await?;

    let proxy_base = format!("http://{}:{}", args.host, args.port);
    let ResolvedEnv {
        env_vars,
        warnings,
        wired_credentials,
    } = resolve_env_for_agent(&mut vault, &warden_config, &args.agent, &proxy_base)?;

    if let Some(max_cost) = args.max_cost {
        if max_cost <= 0.0 {
            anyhow::bail!("--max-cost must be greater than 0");
        }
        for cred in &wired_credentials {
            vault.set_budget(
                cred,
                Some(BudgetConfig {
                    max_usd: max_cost,
                    window: BudgetWindow::Total,
                    mode: BudgetMode::Hard,
                }),
            )?;
        }
        if !wired_credentials.is_empty() {
            eprintln!(
                "wardn: capped {} at ${max_cost:.2} total (persists — clear with `wardn budget clear <credential>`)",
                wired_credentials.join(", ")
            );
        }
    }

    // Drop the decrypted vault from memory before spawning the child — we
    // only needed it to resolve placeholders (and, if --max-cost was set,
    // write the budget cap above).
    drop(vault);

    for w in &warnings {
        eprintln!("warning: {w}");
    }

    if env_vars.is_empty() {
        eprintln!(
            "warning: no known credentials found for agent '{}' — the child \
             process will run with no wardn-injected env vars. Configure one \
             with, e.g.: wardn vault set ANTHROPIC_KEY",
            args.agent
        );
    } else {
        eprintln!(
            "wardn: routing '{}' through {proxy_base} as agent '{}' ({} credential{} wired)",
            cmd,
            args.agent,
            env_vars.len() / 2, // rough: base_url + at least one auth var per credential
            if env_vars.len() > 2 { "s" } else { "" }
        );
    }

    let status = std::process::Command::new(cmd)
        .args(cmd_args)
        .envs(&env_vars)
        .status()
        .with_context(|| format!("failed to launch '{cmd}'"))?;

    std::process::exit(status.code().unwrap_or(1));
}

fn resolve_passphrase(vault_path: &Path) -> Result<String> {
    if let Ok(pass) = std::env::var("WARDN_PASSPHRASE") {
        return Ok(pass);
    }
    if let Some(pass) = wardn::vault::keyring_store::retrieve_passphrase(vault_path) {
        return Ok(pass);
    }

    let pass = rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?;
    if let Err(e) = wardn::vault::keyring_store::store_passphrase(vault_path, &pass) {
        eprintln!("warning: could not save passphrase to the OS keychain ({e})");
    }
    Ok(pass)
}

/// Result of wiring up env vars for an agent.
struct ResolvedEnv {
    env_vars: HashMap<String, String>,
    warnings: Vec<String>,
    /// Credential names that ended up wired — used by `--max-cost` to know
    /// which credentials to cap.
    wired_credentials: Vec<String>,
}

/// Resolve which env vars to set on the child process for the given agent,
/// covering both built-in providers and any custom `[upstreams]` entries.
fn resolve_env_for_agent(
    vault: &mut Vault,
    config: &WardenConfig,
    agent_id: &str,
    proxy_base: &str,
) -> Result<ResolvedEnv> {
    let mut env_vars = HashMap::new();
    let mut warnings = Vec::new();
    let mut wired_credentials = Vec::new();

    for mapping in KNOWN_PROVIDERS {
        if config.upstreams.contains_key(mapping.slug) {
            apply_mapping(
                vault,
                agent_id,
                proxy_base,
                mapping.slug,
                mapping.credential_names,
                mapping.base_url_env,
                mapping.auth_env_vars,
                &mut env_vars,
                &mut warnings,
                &mut wired_credentials,
            )?;
        }
    }

    let known_slugs: Vec<&str> = KNOWN_PROVIDERS.iter().map(|m| m.slug).collect();
    for slug in config.upstreams.keys() {
        if known_slugs.contains(&slug.as_str()) {
            continue;
        }
        let upper = slug.to_uppercase();
        let cred_name = format!("{upper}_KEY");
        let base_url_env = format!("{upper}_BASE_URL");
        let auth_env = format!("{upper}_API_KEY");
        apply_mapping(
            vault,
            agent_id,
            proxy_base,
            slug,
            &[cred_name.as_str()],
            &base_url_env,
            &[auth_env.as_str()],
            &mut env_vars,
            &mut warnings,
            &mut wired_credentials,
        )?;
    }

    Ok(ResolvedEnv {
        env_vars,
        warnings,
        wired_credentials,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_mapping(
    vault: &mut Vault,
    agent_id: &str,
    proxy_base: &str,
    slug: &str,
    credential_names: &[&str],
    base_url_env: &str,
    auth_env_vars: &[&str],
    env_vars: &mut HashMap<String, String>,
    warnings: &mut Vec<String>,
    wired_credentials: &mut Vec<String>,
) -> Result<()> {
    let cred_name = match credential_names
        .iter()
        .find(|name| vault.get(name).is_some())
    {
        Some(name) => *name,
        None => return Ok(()), // no matching credential stored — nothing to wire up
    };

    if !vault.is_agent_authorized(cred_name, agent_id) {
        warnings.push(format!(
            "agent '{agent_id}' is not authorized for credential '{cred_name}' — skipping {base_url_env}"
        ));
        return Ok(());
    }

    let placeholder = vault
        .get_placeholder(cred_name, agent_id)
        .with_context(|| format!("failed to get placeholder for {cred_name}"))?;

    env_vars.insert(base_url_env.to_string(), format!("{proxy_base}/{slug}"));
    for var in auth_env_vars {
        if let Ok(existing) = std::env::var(var) {
            if !existing.starts_with("wdn_placeholder_") {
                warnings.push(format!(
                    "overriding existing {var} in the environment — the child \
                     process will see a wardn placeholder instead of the real value"
                ));
            }
        }
        env_vars.insert(var.to_string(), placeholder.to_string());
    }

    wired_credentials.push(cred_name.to_string());
    Ok(())
}

/// Ensure a wardn daemon is listening on `host:port`, starting one in the
/// background if not.
///
/// This is a best-effort background spawn (`.spawn()` without a double
/// fork/session detach), not a fully daemonized process — it's enough for
/// the common case (a shell session that outlives the launched agent) and
/// for subsequent `wardn run` calls to find it already up via the health
/// check below, but it isn't guaranteed to survive the parent's terminal
/// session closing on every platform.
async fn ensure_daemon_running(
    host: &str,
    port: u16,
    vault_path: &Path,
    config_path: Option<&Path>,
    passphrase: &str,
) -> Result<()> {
    let health_url = format!("http://{host}:{port}/health");
    if is_daemon_up(&health_url).await {
        return Ok(());
    }

    eprintln!("wardn: no daemon running on {host}:{port} — starting one...");

    let wardn_bin = std::env::current_exe().context("failed to resolve wardn binary path")?;
    let mut cmd = std::process::Command::new(wardn_bin);
    cmd.args(["serve", "--host", host, "--port", &port.to_string()])
        .arg("--vault")
        .arg(vault_path)
        .env("WARDN_PASSPHRASE", passphrase)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(cfg) = config_path {
        cmd.arg("--config").arg(cfg);
    }

    let child = cmd
        .spawn()
        .context("failed to spawn wardn serve in the background")?;

    write_daemon_pidfile(vault_path, port, child.id());

    wait_for_daemon(&health_url).await
}

async fn is_daemon_up(health_url: &str) -> bool {
    reqwest::Client::new()
        .get(health_url)
        .timeout(Duration::from_millis(500))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

async fn wait_for_daemon(health_url: &str) -> Result<()> {
    // ~10s at 200ms intervals.
    for _ in 0..50 {
        if is_daemon_up(health_url).await {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    anyhow::bail!("wardn daemon did not become healthy in time — check `wardn serve` manually")
}

/// Best-effort pidfile next to the vault, so a background daemon spawned by
/// `wardn run` can be found and stopped later (e.g. by tests, or a future
/// `wardn stop`). Never fatal if this fails.
fn write_daemon_pidfile(vault_path: &Path, port: u16, pid: u32) {
    let Some(dir) = vault_path.parent() else {
        return;
    };
    let pidfile = dir.join(format!(".wardn-daemon-{port}.pid"));
    let _ = std::fs::write(pidfile, pid.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardn::config::CredentialConfig;

    fn vault_with(cred_name: &str, value: &str, allowed_agents: Vec<&str>) -> Vault {
        let mut vault = Vault::ephemeral();
        vault
            .set_with_config(
                cred_name,
                value,
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: allowed_agents.into_iter().map(String::from).collect(),
                    allowed_domains: vec![],
                    rate_limit: None,
                },
            )
            .unwrap();
        vault
    }

    #[test]
    fn test_resolve_env_wires_anthropic_by_default() {
        let mut vault = vault_with("ANTHROPIC_KEY", "sk-ant-real", vec![]);
        let config = WardenConfig::default();

        let ResolvedEnv {
            env_vars,
            warnings,
            wired_credentials: wired,
        } = resolve_env_for_agent(&mut vault, &config, "claude-code", "http://127.0.0.1:7777")
            .unwrap();

        assert!(warnings.is_empty());
        assert_eq!(
            env_vars.get("ANTHROPIC_BASE_URL").unwrap(),
            "http://127.0.0.1:7777/anthropic"
        );
        let token = env_vars.get("ANTHROPIC_AUTH_TOKEN").unwrap();
        assert!(token.starts_with("wdn_placeholder_"));
        assert_eq!(env_vars.get("ANTHROPIC_API_KEY").unwrap(), token);
        // OpenAI wasn't configured in the vault, so nothing for it.
        assert!(!env_vars.contains_key("OPENAI_BASE_URL"));
        assert_eq!(wired, vec!["ANTHROPIC_KEY".to_string()]);
    }

    #[test]
    fn test_resolve_env_wires_both_providers_when_both_configured() {
        let mut vault = Vault::ephemeral();
        vault.set("ANTHROPIC_KEY", "sk-ant-real").unwrap();
        vault.set("OPENAI_KEY", "sk-proj-real").unwrap();
        let config = WardenConfig::default();

        let ResolvedEnv {
            env_vars,
            wired_credentials: wired,
            ..
        } = resolve_env_for_agent(&mut vault, &config, "agent", "http://127.0.0.1:7777").unwrap();

        assert!(env_vars.contains_key("ANTHROPIC_BASE_URL"));
        assert!(env_vars.contains_key("OPENAI_BASE_URL"));
        assert_eq!(wired.len(), 2);
        assert_eq!(
            env_vars.get("OPENAI_BASE_URL").unwrap(),
            "http://127.0.0.1:7777/openai"
        );
    }

    #[test]
    fn test_resolve_env_skips_unauthorized_agent_with_warning() {
        let mut vault = vault_with("ANTHROPIC_KEY", "sk-ant-real", vec!["only-this-agent"]);
        let config = WardenConfig::default();

        let ResolvedEnv {
            env_vars,
            warnings,
            wired_credentials: wired,
        } = resolve_env_for_agent(&mut vault, &config, "someone-else", "http://127.0.0.1:7777")
            .unwrap();

        assert!(env_vars.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("not authorized"));
        assert!(wired.is_empty());
    }

    #[test]
    fn test_resolve_env_empty_vault_produces_no_env_vars() {
        let mut vault = Vault::ephemeral();
        let config = WardenConfig::default();

        let ResolvedEnv {
            env_vars,
            warnings,
            wired_credentials: wired,
        } = resolve_env_for_agent(&mut vault, &config, "agent", "http://127.0.0.1:7777").unwrap();

        assert!(env_vars.is_empty());
        assert!(warnings.is_empty());
        assert!(wired.is_empty());
    }

    #[test]
    fn test_resolve_env_custom_upstream_uses_slug_key_convention() {
        let mut vault = Vault::ephemeral();
        vault.set("MYAPI_KEY", "sk-custom-real").unwrap();

        let mut config = WardenConfig::default();
        config.upstreams.insert(
            "myapi".to_string(),
            "https://internal.example.com".to_string(),
        );

        let ResolvedEnv {
            env_vars,
            wired_credentials: wired,
            ..
        } = resolve_env_for_agent(&mut vault, &config, "agent", "http://127.0.0.1:7777").unwrap();

        assert_eq!(
            env_vars.get("MYAPI_BASE_URL").unwrap(),
            "http://127.0.0.1:7777/myapi"
        );
        assert!(env_vars
            .get("MYAPI_API_KEY")
            .unwrap()
            .starts_with("wdn_placeholder_"));
        assert_eq!(wired, vec!["MYAPI_KEY".to_string()]);
    }

    #[test]
    fn test_resolve_env_is_idempotent_across_calls() {
        // Calling resolve_env_for_agent twice for the same agent should
        // return the SAME placeholder both times (placeholders are
        // per-credential-per-agent, not minted fresh every run).
        let mut vault = vault_with("ANTHROPIC_KEY", "sk-ant-real", vec![]);
        let config = WardenConfig::default();

        let first =
            resolve_env_for_agent(&mut vault, &config, "agent", "http://127.0.0.1:7777").unwrap();
        let second =
            resolve_env_for_agent(&mut vault, &config, "agent", "http://127.0.0.1:7777").unwrap();

        assert_eq!(
            first.env_vars.get("ANTHROPIC_AUTH_TOKEN"),
            second.env_vars.get("ANTHROPIC_AUTH_TOKEN")
        );
    }
}
