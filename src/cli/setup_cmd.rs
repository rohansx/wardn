use std::path::Path;

use anyhow::{Context, Result};

use super::SetupCommands;

pub fn run(cmd: &SetupCommands, vault_path: &Path) -> Result<()> {
    match cmd {
        SetupCommands::ClaudeCode { alias } => setup_claude_code(vault_path, *alias),
        SetupCommands::Cursor => setup_cursor(vault_path),
        SetupCommands::Codex => setup_generic_alias(vault_path, "codex", "codex"),
        SetupCommands::Gemini => setup_generic_alias(vault_path, "gemini", "gemini-cli"),
        SetupCommands::OpenCode => setup_generic_alias(vault_path, "opencode", "opencode"),
        SetupCommands::Aider => setup_generic_alias(vault_path, "aider", "aider"),
    }
}

/// Resolve the vault passphrase (env var, then OS keychain, then prompt),
/// verify it actually opens the vault, and store it in the OS keychain for
/// next time.
///
/// The passphrase is deliberately never written into an agent's own config
/// file (MCP env blocks, etc.) — see `setup_claude_code`/`setup_cursor`
/// below. A subprocess spawned by the IDE (`wardn serve --mcp`) instead
/// retrieves it from the keychain itself at startup.
fn get_passphrase(vault_path: &Path) -> Result<String> {
    let passphrase = if let Ok(pass) = std::env::var("WARDN_PASSPHRASE") {
        pass
    } else if let Some(pass) = wardn::vault::keyring_store::retrieve_passphrase(vault_path) {
        pass
    } else {
        rpassword::prompt_password("Vault passphrase: ").context("failed to read passphrase")?
    };

    // Verify it works
    wardn::Vault::open(vault_path, &passphrase)
        .context("failed to open vault — wrong passphrase?")?;

    if let Err(e) = wardn::vault::keyring_store::store_passphrase(vault_path, &passphrase) {
        eprintln!(
            "warning: could not save passphrase to the OS keychain ({e}).\n\
             You'll need to set WARDN_PASSPHRASE yourself when wardn's MCP server starts."
        );
    }

    Ok(passphrase)
}

/// Register wardn as an MCP server in Claude Code via `claude mcp add`.
fn setup_claude_code(vault_path: &Path, add_alias: bool) -> Result<()> {
    let wardn_bin = find_wardn_binary()?;
    let vault_abs = std::fs::canonicalize(vault_path).unwrap_or_else(|_| vault_path.to_path_buf());
    let vault_str = vault_abs.to_str().unwrap_or("~/.vibeguard/vault.enc");

    println!("Setting up wardn for Claude Code...\n");

    // Verify vault exists and passphrase works
    if !vault_path.exists() {
        anyhow::bail!(
            "vault not found at {}. Create one first:\n  wardn vault create",
            vault_path.display()
        );
    }
    // Verifies the passphrase and stores it in the OS keychain — the
    // spawned `wardn serve --mcp` subprocess retrieves it from there, so it
    // never needs to be written into Claude Code's own config file.
    get_passphrase(vault_path)?;

    // Check if claude CLI exists
    let claude_check = std::process::Command::new("claude")
        .arg("--version")
        .output();

    if claude_check.is_err() || !claude_check.unwrap().status.success() {
        eprintln!("error: 'claude' CLI not found. Install Claude Code first:");
        eprintln!("  https://claude.ai/code");
        std::process::exit(1);
    }

    // Remove existing wardn entry if present (to update env)
    let _ = std::process::Command::new("claude")
        .args(["mcp", "remove", "wardn"])
        .output();

    let status = std::process::Command::new("claude")
        .args(claude_mcp_add_args(&wardn_bin, vault_str))
        .status()
        .context("failed to run 'claude mcp add'")?;

    if !status.success() {
        eprintln!("failed to register wardn MCP server");
        std::process::exit(1);
    }

    print_success("Claude Code", "claude mcp list");

    if add_alias {
        println!();
        add_shell_alias(&wardn_bin, "claude", "claude-code")?;
    } else {
        println!();
        println!("Tip: run with --alias to make plain `claude` transparently");
        println!("route through `wardn run` (adds a shell alias).");
    }

    Ok(())
}

/// Register wardn as an MCP server in Cursor via ~/.cursor/mcp.json.
fn setup_cursor(vault_path: &Path) -> Result<()> {
    let wardn_bin = find_wardn_binary()?;
    let vault_abs = std::fs::canonicalize(vault_path).unwrap_or_else(|_| vault_path.to_path_buf());
    let vault_str = vault_abs.to_str().unwrap_or("~/.vibeguard/vault.enc");

    println!("Setting up wardn for Cursor...\n");

    // Verify vault exists and passphrase works
    if !vault_path.exists() {
        anyhow::bail!(
            "vault not found at {}. Create one first:\n  wardn vault create",
            vault_path.display()
        );
    }
    // Verifies the passphrase and stores it in the OS keychain — the
    // spawned `wardn serve --mcp` subprocess retrieves it from there, so it
    // never needs to be written into ~/.cursor/mcp.json.
    get_passphrase(vault_path)?;

    let cursor_dir = dirs_cursor();
    let mcp_path = cursor_dir.join("mcp.json");

    // Read existing config or create new
    let mut config: serde_json::Value = if mcp_path.exists() {
        let content =
            std::fs::read_to_string(&mcp_path).context("failed to read ~/.cursor/mcp.json")?;
        if content.trim().is_empty() {
            serde_json::json!({ "mcpServers": {} })
        } else {
            serde_json::from_str(&content).context("failed to parse ~/.cursor/mcp.json")?
        }
    } else {
        std::fs::create_dir_all(&cursor_dir).context("failed to create ~/.cursor/")?;
        serde_json::json!({ "mcpServers": {} })
    };

    // Add wardn server entry
    let servers = config
        .as_object_mut()
        .context("invalid mcp.json format")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    servers
        .as_object_mut()
        .context("mcpServers must be an object")?
        .insert(
            "wardn".to_string(),
            cursor_server_entry(&wardn_bin, vault_str),
        );

    // Write back
    let formatted =
        serde_json::to_string_pretty(&config).context("failed to serialize mcp.json")?;
    std::fs::write(&mcp_path, formatted).context("failed to write ~/.cursor/mcp.json")?;

    println!("wrote {}", mcp_path.display());
    print_success("Cursor", "Cursor Settings → Features → MCP");
    Ok(())
}

/// Set up wardn for a CLI agent that has no MCP integration of its own
/// (or none wardn fabricates a config format for) — Codex, Gemini CLI,
/// OpenCode, Aider. The only thing that actually routes an agent's traffic
/// through wardn is `wardn run` (see P0.1/P0.5), so unlike Claude
/// Code/Cursor's MCP registration, this goes straight to a shell alias:
/// `{binary_name}` becomes `wardn run --agent {agent_id} -- {binary_name}`.
///
/// This is deliberately the same mechanism as `wardn setup claude-code
/// --alias`, generalized — these CLIs all read their provider API key from
/// an env var, so pointing that env var at the proxy via `wardn run` is a
/// mechanism that works regardless of whether the tool has any MCP support.
fn setup_generic_alias(vault_path: &Path, binary_name: &str, agent_id: &str) -> Result<()> {
    let wardn_bin = find_wardn_binary()?;

    println!("Setting up wardn for {binary_name}...\n");

    if !vault_path.exists() {
        anyhow::bail!(
            "vault not found at {}. Create one first:\n  wardn vault create",
            vault_path.display()
        );
    }
    get_passphrase(vault_path)?;

    add_shell_alias(&wardn_bin, binary_name, agent_id)?;

    println!();
    println!("wardn will now route `{binary_name}` through the proxy — real API keys");
    println!("are injected at the network layer, {binary_name} never sees them.");
    println!();
    println!("Restart your shell (or `source` your rc file), then run `{binary_name}` as usual.");
    println!("Make sure a credential is wired for it first, e.g.: wardn vault set ANTHROPIC_KEY");
    Ok(())
}

fn print_success(tool: &str, verify_cmd: &str) {
    println!("\nwardn registered as MCP server in {tool}.");
    println!("Passphrase saved to the OS keychain — not written into {tool}'s config file.");
    println!();
    println!("MCP tools available:");
    println!("  get_credential_ref  — get a placeholder token for a credential");
    println!("  list_credentials    — list available credentials");
    println!("  check_rate_limit    — check remaining quota");
    println!();
    println!("When the agent needs an API key, it calls get_credential_ref");
    println!("and receives a placeholder token (never the real key).");
    println!();
    println!("To actually route the agent's traffic through wardn (so the");
    println!("real key gets injected at the network layer), launch it via:");
    println!("  wardn run --agent <name> -- <agent-command...>");
    println!();
    println!("Restart {tool}, then verify with:");
    println!("  {verify_cmd}");
}

/// Find the wardn binary path.
fn find_wardn_binary() -> Result<String> {
    if let Ok(current_exe) = std::env::current_exe() {
        if current_exe
            .file_name()
            .map(|f| f == "wardn")
            .unwrap_or(false)
        {
            return Ok(current_exe.to_string_lossy().to_string());
        }
    }

    let which = std::process::Command::new("which").arg("wardn").output();

    if let Ok(output) = which {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
    }

    Ok("wardn".to_string())
}

fn dirs_cursor() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join(".cursor")
}

/// Pick the shell rc file + alias line for the user's `$SHELL`, so
/// `{binary_name}` transparently becomes
/// `wardn run --agent {agent_id} -- {binary_name}`.
///
/// MCP registration alone (Claude Code/Cursor's `setup`) only lets the tool
/// call wardn's MCP tools — it does NOT route the tool's own API traffic
/// through the proxy. This alias is the only way to make that automatic
/// without the user remembering to type `wardn run -- <cmd>` every time.
fn alias_for_shell(
    shell: &str,
    home: &str,
    wardn_bin: &str,
    binary_name: &str,
    agent_id: &str,
) -> (std::path::PathBuf, String) {
    let cmd = format!("{wardn_bin} run --agent {agent_id} -- {binary_name}");
    if shell.contains("fish") {
        (
            std::path::PathBuf::from(home).join(".config/fish/config.fish"),
            format!("alias {binary_name} '{cmd}'"),
        )
    } else if shell.contains("zsh") {
        (
            std::path::PathBuf::from(home).join(".zshrc"),
            format!("alias {binary_name}=\"{cmd}\""),
        )
    } else {
        (
            std::path::PathBuf::from(home).join(".bashrc"),
            format!("alias {binary_name}=\"{cmd}\""),
        )
    }
}

fn add_shell_alias(wardn_bin: &str, binary_name: &str, agent_id: &str) -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    add_shell_alias_at(wardn_bin, &shell, &home, binary_name, agent_id)
}

fn add_shell_alias_at(
    wardn_bin: &str,
    shell: &str,
    home: &str,
    binary_name: &str,
    agent_id: &str,
) -> Result<()> {
    let (rc_path, alias_line) = alias_for_shell(shell, home, wardn_bin, binary_name, agent_id);

    let existing = std::fs::read_to_string(&rc_path).unwrap_or_default();
    if existing.contains(&alias_line) {
        println!("shell alias already present in {}", rc_path.display());
        return Ok(());
    }

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_path)
        .with_context(|| format!("failed to open {}", rc_path.display()))?;
    writeln!(file, "\n# added by `wardn setup {agent_id} --alias`")?;
    writeln!(file, "{alias_line}")?;

    println!("added alias to {}", rc_path.display());
    println!("restart your shell or run: source {}", rc_path.display());
    Ok(())
}

/// Build the `claude mcp add` argument list for registering wardn.
///
/// Deliberately carries no `-e WARDN_PASSPHRASE=...` — the spawned
/// `wardn serve --mcp` process resolves the passphrase from the OS
/// keychain instead. See `get_passphrase`.
fn claude_mcp_add_args(wardn_bin: &str, vault_str: &str) -> Vec<String> {
    vec![
        "mcp".to_string(),
        "add".to_string(),
        "--transport".to_string(),
        "stdio".to_string(),
        "--scope".to_string(),
        "user".to_string(),
        "wardn".to_string(),
        "--".to_string(),
        wardn_bin.to_string(),
        "serve".to_string(),
        "--mcp".to_string(),
        "--agent".to_string(),
        "claude-code".to_string(),
        "--vault".to_string(),
        vault_str.to_string(),
    ]
}

/// Build the `mcpServers.wardn` entry written to `~/.cursor/mcp.json`.
///
/// Deliberately carries no `env` block — see `claude_mcp_add_args`.
fn cursor_server_entry(wardn_bin: &str, vault_str: &str) -> serde_json::Value {
    serde_json::json!({
        "command": wardn_bin,
        "args": ["serve", "--mcp", "--agent", "cursor", "--vault", vault_str],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claude_mcp_add_args_never_contains_passphrase() {
        let args = claude_mcp_add_args("/usr/local/bin/wardn", "/home/u/.vibeguard/vault.enc");
        let joined = args.join(" ");
        assert!(!joined.contains("WARDN_PASSPHRASE"));
        assert!(!joined.contains("-e"));
        assert!(joined.contains("--vault"));
    }

    #[test]
    fn test_cursor_server_entry_never_contains_passphrase() {
        let entry = cursor_server_entry("/usr/local/bin/wardn", "/home/u/.vibeguard/vault.enc");
        let serialized = entry.to_string();
        assert!(!serialized.contains("WARDN_PASSPHRASE"));
        assert!(
            entry.get("env").is_none(),
            "no env block should be present at all"
        );
        assert_eq!(entry["command"], "/usr/local/bin/wardn");
    }

    #[test]
    fn test_alias_for_zsh() {
        let (path, line) = alias_for_shell(
            "/bin/zsh",
            "/home/u",
            "/usr/local/bin/wardn",
            "claude",
            "claude-code",
        );
        assert_eq!(path, std::path::PathBuf::from("/home/u/.zshrc"));
        assert_eq!(
            line,
            "alias claude=\"/usr/local/bin/wardn run --agent claude-code -- claude\""
        );
    }

    #[test]
    fn test_alias_for_fish() {
        let (path, line) = alias_for_shell(
            "/usr/bin/fish",
            "/home/u",
            "/usr/local/bin/wardn",
            "claude",
            "claude-code",
        );
        assert_eq!(
            path,
            std::path::PathBuf::from("/home/u/.config/fish/config.fish")
        );
        assert_eq!(
            line,
            "alias claude '/usr/local/bin/wardn run --agent claude-code -- claude'"
        );
    }

    #[test]
    fn test_alias_for_other_agent_uses_its_own_binary_name() {
        let (path, line) = alias_for_shell(
            "/bin/zsh",
            "/home/u",
            "/usr/local/bin/wardn",
            "codex",
            "codex",
        );
        assert_eq!(path, std::path::PathBuf::from("/home/u/.zshrc"));
        assert_eq!(
            line,
            "alias codex=\"/usr/local/bin/wardn run --agent codex -- codex\""
        );
    }

    #[test]
    fn test_alias_defaults_to_bashrc_for_unknown_shell() {
        let (path, line) = alias_for_shell(
            "/bin/bash",
            "/home/u",
            "/usr/local/bin/wardn",
            "claude",
            "claude-code",
        );
        assert_eq!(path, std::path::PathBuf::from("/home/u/.bashrc"));
        assert!(line.contains("wardn run --agent claude-code -- claude"));
    }

    #[test]
    fn test_add_shell_alias_is_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().to_str().unwrap();

        add_shell_alias_at(
            "/usr/local/bin/wardn",
            "/bin/bash",
            home,
            "claude",
            "claude-code",
        )
        .unwrap();
        let rc_path = dir.path().join(".bashrc");
        let first = std::fs::read_to_string(&rc_path).unwrap();
        assert!(first.contains("alias claude="));

        // Running it again must not duplicate the alias line.
        add_shell_alias_at(
            "/usr/local/bin/wardn",
            "/bin/bash",
            home,
            "claude",
            "claude-code",
        )
        .unwrap();
        let second = std::fs::read_to_string(&rc_path).unwrap();
        assert_eq!(
            second.matches("alias claude=").count(),
            1,
            "alias should only be added once: {second}"
        );
    }
}
