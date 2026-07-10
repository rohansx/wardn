pub mod budget_cmd;
pub mod import_cmd;
pub mod migrate_cmd;
pub mod run_cmd;
pub mod serve_cmd;
pub mod setup_cmd;
pub mod vault_cmd;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "wardn",
    about = "Credential isolation for AI agents",
    version,
    propagate_version = true
)]
pub struct Cli {
    /// Path to the vault file
    #[arg(long, global = true, default_value = "~/.vibeguard/vault.enc")]
    pub vault: String,

    /// Path to the wardn config file (TOML)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage the encrypted credential vault
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },

    /// Start the wardn proxy server
    Serve(ServeArgs),

    /// Launch an agent with its traffic routed through wardn.
    ///
    /// Lazy-starts the proxy daemon if it isn't already running, resolves
    /// placeholders for known credentials, points the child process at the
    /// proxy via base-URL env vars, and execs it. This is what actually
    /// wires an agent's real traffic through wardn — `wardn setup` alone
    /// only registers the MCP server.
    Run(RunArgs),

    /// Manage dollar-denominated spend caps ("denial of wallet" protection)
    Budget {
        #[command(subcommand)]
        command: BudgetCommands,
    },

    /// Scan for exposed credentials and migrate them
    Migrate(MigrateArgs),

    /// Import credentials into the vault from external sources
    Import {
        #[command(subcommand)]
        command: ImportCommands,
    },

    /// Set up wardn integration with AI tools
    Setup {
        #[command(subcommand)]
        command: SetupCommands,
    },
}

#[derive(Subcommand)]
pub enum VaultCommands {
    /// Create a new encrypted vault
    Create,

    /// Store a credential in the vault
    Set {
        /// Credential name (e.g. OPENAI_KEY)
        key: String,

        /// Restrict this credential to specific domain(s) — repeatable
        /// (--domain api.openai.com --domain api.example.com). Without
        /// this, a leaked placeholder can be pointed at ANY domain through
        /// the proxy, injecting the real key into a request to an
        /// attacker's server. If omitted interactively, you'll be
        /// prompted; in non-interactive/scripted use (WARDN_VALUE set)
        /// it defaults to unrestricted with a loud warning.
        #[arg(long = "domain")]
        domains: Vec<String>,
    },

    /// Get the placeholder token for a credential (never the real value)
    Get {
        /// Credential name
        key: String,

        /// Agent identity for the placeholder
        #[arg(long, default_value = "cli")]
        agent: String,
    },

    /// List all stored credentials (names only, no values)
    List,

    /// Rotate a credential value (placeholder stays the same)
    Rotate {
        /// Credential name to rotate
        key: String,
    },

    /// Remove a credential from the vault
    Remove {
        /// Credential name to remove
        key: String,
    },
}

#[derive(Parser)]
pub struct ServeArgs {
    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, default_value_t = 7777)]
    pub port: u16,

    /// Also start the MCP server over stdio
    #[arg(long)]
    pub mcp: bool,

    /// Agent identity for MCP server (required with --mcp)
    #[arg(long)]
    pub agent: Option<String>,
}

#[derive(Parser)]
pub struct RunArgs {
    /// Agent identity — determines which credentials/placeholders are used
    /// and which ACLs/rate limits apply.
    #[arg(long, default_value = "cli")]
    pub agent: String,

    /// Host the wardn proxy binds to (and is looked for / started on).
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port the wardn proxy binds to.
    #[arg(long, default_value_t = 7777)]
    pub port: u16,

    /// Cap total spend on every credential this agent uses at this many
    /// USD (hard stop, resets never — a lifetime cap). This SETS the
    /// credential's budget in the vault (same as `wardn budget set`), so
    /// it persists after this run exits — clear it with `wardn budget
    /// clear <credential>` if you don't want it to carry over.
    #[arg(long, value_name = "USD")]
    pub max_cost: Option<f64>,

    /// The command to run, e.g. `wardn run -- claude`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Parser)]
pub struct MigrateArgs {
    /// Source system to scan
    #[arg(long, value_enum, default_value = "claude-code")]
    pub source: MigrateSourceArg,

    /// Directory to scan (for --source directory)
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// Audit only — don't migrate credentials
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Clone, ValueEnum)]
pub enum MigrateSourceArg {
    ClaudeCode,
    OpenClaw,
    Directory,
}

#[derive(Subcommand)]
pub enum ImportCommands {
    /// Parse a classic .env file (KEY=value, comments, optional `export`,
    /// single/double-quoted values with backslash escapes).
    Dotenv {
        /// Path to the .env file
        path: PathBuf,
    },

    /// Import credentials from a JSON or YAML file. Format: either a flat
    /// `{KEY: value}` map or a structured `{credentials: [{name, value}, ...]}`.
    /// Format is inferred from extension (`.json`, `.yaml`, `.yml`).
    File {
        /// Path to the JSON or YAML file
        path: PathBuf,
    },

    /// Import credentials from 1Password via the `op` CLI. Reuses your
    /// signed-in `op` session; runs `op read <REF>` and stores the result.
    /// Default name is derived from the ref's last segment; override with --name.
    OnePassword {
        /// `op://vault/item/field` reference
        #[arg(value_name = "REF")]
        ref_arg: String,

        /// Override the credential name (otherwise derived from the ref)
        #[arg(long)]
        name: Option<String>,
    },

    /// Read .env-formatted KEY=value lines from stdin. Useful for piping:
    ///   echo 'OPENAI_KEY=sk-...' | wardn import stdin
    Stdin,
}

#[derive(Subcommand)]
pub enum BudgetCommands {
    /// Set a dollar spend cap on a credential (applies per agent — each
    /// authorized agent gets its own independent budget of this size).
    Set {
        /// Credential name (e.g. OPENAI_KEY)
        credential: String,

        /// Max spend in USD before requests are blocked (hard mode) or
        /// flagged (soft mode).
        #[arg(long, value_name = "USD")]
        usd: f64,

        /// How often the spend counter resets.
        #[arg(long, value_enum, default_value = "day")]
        window: BudgetWindowArg,

        /// hard = block once exceeded. soft = allow but flag/log.
        #[arg(long, value_enum, default_value = "hard")]
        mode: BudgetModeArg,
    },

    /// Remove the spend cap from a credential (unlimited again).
    Clear {
        /// Credential name to clear the budget from
        credential: String,
    },

    /// Show live spend against configured budgets — queries the running
    /// wardn daemon (needs `wardn serve` or `wardn run` already up).
    Status {
        /// Agent identity to show spend for
        #[arg(long, default_value = "cli")]
        agent: String,

        /// Host the wardn daemon is running on
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Port the wardn daemon is running on
        #[arg(long, default_value_t = 7777)]
        port: u16,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum BudgetWindowArg {
    Hour,
    Day,
    Week,
    Month,
    Total,
}

impl From<BudgetWindowArg> for wardn::config::BudgetWindow {
    fn from(arg: BudgetWindowArg) -> Self {
        match arg {
            BudgetWindowArg::Hour => wardn::config::BudgetWindow::Hour,
            BudgetWindowArg::Day => wardn::config::BudgetWindow::Day,
            BudgetWindowArg::Week => wardn::config::BudgetWindow::Week,
            BudgetWindowArg::Month => wardn::config::BudgetWindow::Month,
            BudgetWindowArg::Total => wardn::config::BudgetWindow::Total,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum BudgetModeArg {
    Hard,
    Soft,
}

impl From<BudgetModeArg> for wardn::config::BudgetMode {
    fn from(arg: BudgetModeArg) -> Self {
        match arg {
            BudgetModeArg::Hard => wardn::config::BudgetMode::Hard,
            BudgetModeArg::Soft => wardn::config::BudgetMode::Soft,
        }
    }
}

#[derive(Subcommand)]
pub enum SetupCommands {
    /// Register wardn as an MCP server in Claude Code
    ClaudeCode {
        /// Also add a shell alias so plain `claude` transparently routes
        /// through `wardn run` — without this, MCP registration alone does
        /// NOT put the agent's traffic through the wardn proxy.
        #[arg(long)]
        alias: bool,
    },

    /// Register wardn as an MCP server in Cursor
    Cursor,

    /// Add a shell alias so `codex` transparently routes through
    /// `wardn run` — Codex has no wardn-fabricated MCP config here, so
    /// this is the only integration path (same mechanism as
    /// `claude-code --alias`, see `wardn run`).
    Codex,

    /// Add a shell alias so `gemini` transparently routes through
    /// `wardn run`.
    Gemini,

    /// Add a shell alias so `opencode` transparently routes through
    /// `wardn run`.
    OpenCode,

    /// Add a shell alias so `aider` transparently routes through
    /// `wardn run`.
    Aider,
}
