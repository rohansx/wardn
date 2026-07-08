mod cli;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands};
use wardn::config::expand_tilde;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Cli::parse();
    let vault_path = expand_tilde(&args.vault);

    let result = match &args.command {
        Commands::Vault { command } => cli::vault_cmd::run(command, &vault_path),

        Commands::Serve(serve_args) => {
            cli::serve_cmd::run(serve_args, &vault_path, args.config.as_deref()).await
        }

        Commands::Run(run_args) => {
            cli::run_cmd::run(run_args, &vault_path, args.config.as_deref()).await
        }

        Commands::Migrate(migrate_args) => cli::migrate_cmd::run(migrate_args, &vault_path),

        Commands::Setup { command } => cli::setup_cmd::run(command, &vault_path),

        Commands::Budget { command } => cli::budget_cmd::run(command, &vault_path).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
