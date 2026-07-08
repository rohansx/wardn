use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use wardn::config::BudgetConfig;
use wardn::Vault;

use super::BudgetCommands;

/// Resolve the vault passphrase: env var, then OS keychain, then prompt.
/// Same order as `run`/`serve`/`setup` — see `keyring_store` for why.
fn read_passphrase(vault_path: &Path) -> Result<String> {
    if let Ok(pass) = std::env::var("WARDN_PASSPHRASE") {
        return Ok(pass);
    }
    if let Some(pass) = wardn::vault::keyring_store::retrieve_passphrase(vault_path) {
        return Ok(pass);
    }
    rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")
}

pub async fn run(cmd: &BudgetCommands, vault_path: &Path) -> Result<()> {
    match cmd {
        BudgetCommands::Set {
            credential,
            usd,
            window,
            mode,
        } => set(
            vault_path,
            credential,
            *usd,
            (*window).into(),
            (*mode).into(),
        ),
        BudgetCommands::Clear { credential } => clear(vault_path, credential),
        BudgetCommands::Status { agent, host, port } => status(agent, host, *port).await,
    }
}

fn set(
    vault_path: &Path,
    credential: &str,
    usd: f64,
    window: wardn::config::BudgetWindow,
    mode: wardn::config::BudgetMode,
) -> Result<()> {
    if usd <= 0.0 {
        bail!("--usd must be greater than 0");
    }

    let passphrase = read_passphrase(vault_path)?;
    let mut vault = Vault::open(vault_path, &passphrase)?;

    vault.set_budget(
        credential,
        Some(BudgetConfig {
            max_usd: usd,
            window,
            mode,
        }),
    )?;

    println!(
        "budget set: {credential} capped at ${usd:.2} per {window_desc} ({mode_desc} mode)",
        window_desc = window_description(window),
        mode_desc = mode_description(mode),
    );
    Ok(())
}

fn clear(vault_path: &Path, credential: &str) -> Result<()> {
    let passphrase = read_passphrase(vault_path)?;
    let mut vault = Vault::open(vault_path, &passphrase)?;
    vault.set_budget(credential, None)?;
    println!("budget cleared for {credential} — unlimited again");
    Ok(())
}

async fn status(agent: &str, host: &str, port: u16) -> Result<()> {
    let url = format!("http://{host}:{port}/_wardn/budget?agent={agent}");
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .with_context(|| {
            format!(
                "could not reach wardn daemon at {host}:{port} — is it running?\n  \
                 start one with: wardn serve   (or launch an agent with: wardn run -- <cmd>)"
            )
        })?;

    let body: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse daemon response")?;
    let credentials = body["credentials"].as_array().cloned().unwrap_or_default();

    if credentials.is_empty() {
        println!("no credentials configured for agent '{agent}'");
        return Ok(());
    }

    println!(
        "{:<24} {:<12} {:<12} {:<12} {:<8} WINDOW",
        "CREDENTIAL", "SPENT", "LIMIT", "REMAINING", "MODE"
    );
    println!("{}", "-".repeat(80));

    for cred in &credentials {
        let name = cred["credential"].as_str().unwrap_or("?");
        if cred["configured"].as_bool().unwrap_or(false) {
            let spent = cred["spent_usd"].as_f64().unwrap_or(0.0);
            let max = cred["max_usd"].as_f64().unwrap_or(0.0);
            let remaining = cred["remaining_usd"].as_f64().unwrap_or(0.0);
            let mode = cred["mode"].as_str().unwrap_or("?");
            let window = cred["window"].as_str().unwrap_or("?");
            println!(
                "{name:<24} ${spent:<11.4} ${max:<11.2} ${remaining:<11.2} {mode:<8} {window}"
            );
        } else {
            println!(
                "{name:<24} {:<12} {:<12} {:<12} {:<8} -",
                "-", "unlimited", "-", "-"
            );
        }
    }

    Ok(())
}

fn window_description(window: wardn::config::BudgetWindow) -> &'static str {
    match window {
        wardn::config::BudgetWindow::Hour => "hour",
        wardn::config::BudgetWindow::Day => "day",
        wardn::config::BudgetWindow::Week => "week",
        wardn::config::BudgetWindow::Month => "month",
        wardn::config::BudgetWindow::Total => "total (never resets)",
    }
}

fn mode_description(mode: wardn::config::BudgetMode) -> &'static str {
    match mode {
        wardn::config::BudgetMode::Hard => "hard — blocks",
        wardn::config::BudgetMode::Soft => "soft — flags only",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_description_covers_all_variants() {
        assert_eq!(window_description(wardn::config::BudgetWindow::Day), "day");
        assert_eq!(
            window_description(wardn::config::BudgetWindow::Total),
            "total (never resets)"
        );
    }

    #[test]
    fn test_mode_description_covers_all_variants() {
        assert!(mode_description(wardn::config::BudgetMode::Hard).contains("blocks"));
        assert!(mode_description(wardn::config::BudgetMode::Soft).contains("flags"));
    }
}
