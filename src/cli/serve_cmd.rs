use std::path::Path;

use anyhow::{bail, Context, Result};

use wardn::config::WardenConfig;
use wardn::daemon::{Daemon, DaemonConfig};
use wardn::Vault;

use super::ServeArgs;

pub async fn run(args: &ServeArgs, vault_path: &Path, config_path: Option<&Path>) -> Result<()> {
    if args.mcp && args.agent.is_none() {
        bail!("--agent is required when --mcp is set");
    }

    let passphrase = if let Ok(pass) = std::env::var("WARDN_PASSPHRASE") {
        tracing::warn!("using passphrase from WARDN_PASSPHRASE env var");
        pass
    } else if let Some(pass) = wardn::vault::keyring_store::retrieve_passphrase(vault_path) {
        tracing::info!("using passphrase from OS keychain");
        pass
    } else {
        rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")?
    };

    let vault = Vault::open(vault_path, &passphrase)?;

    let warden_config = match config_path {
        Some(p) => WardenConfig::load(p)?,
        None => WardenConfig::default(),
    };

    let daemon_config = DaemonConfig {
        host: args.host.clone(),
        port: args.port,
        warden_config,
    };

    let daemon = Daemon::new(vault, daemon_config);

    if args.mcp {
        let agent_id = args.agent.clone().unwrap();
        daemon.serve_all(agent_id).await?;
    } else {
        daemon.serve_proxy().await?;
    }

    Ok(())
}
