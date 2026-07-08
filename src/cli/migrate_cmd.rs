use std::path::Path;

use anyhow::{Context, Result};

use wardn::migrate::{self, MigrateSource};
use wardn::Vault;

use super::{MigrateArgs, MigrateSourceArg};

pub fn run(args: &MigrateArgs, vault_path: &Path) -> Result<()> {
    let source = match &args.source {
        MigrateSourceArg::ClaudeCode => MigrateSource::ClaudeCode,
        MigrateSourceArg::OpenClaw => MigrateSource::OpenClaw,
        MigrateSourceArg::Directory => {
            let path = args
                .path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--path is required when --source directory"))?;
            MigrateSource::Directory(path)
        }
    };

    if args.dry_run {
        let report = migrate::run(&source, None, true)?;
        print!("{}", report.to_terminal_string());
    } else {
        let passphrase = if let Ok(pass) = std::env::var("WARDN_PASSPHRASE") {
            tracing::warn!("using passphrase from WARDN_PASSPHRASE env var");
            pass
        } else {
            rpassword::prompt_password("Vault passphrase: ").context("failed to read passphrase")?
        };

        let mut vault = if vault_path.exists() {
            Vault::open(vault_path, &passphrase)?
        } else {
            if let Some(parent) = vault_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            println!("creating new vault at {}", vault_path.display());
            Vault::create(vault_path, &passphrase)?
        };

        let report = migrate::run(&source, Some(&mut vault), false)?;
        print!("{}", report.to_terminal_string());
    }

    Ok(())
}
