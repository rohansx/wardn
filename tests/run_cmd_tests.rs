//! True end-to-end test of `wardn run`: lazy-starts a real background
//! daemon, resolves a placeholder, and launches a child process with the
//! wardn-wired env vars actually set — the central "does the core loop
//! work at all" claim from the revival plan's Reality Check.
//!
//! The spawned background daemon is intentionally not double-forked (see
//! `run_cmd::ensure_daemon_running`), so this test cleans it up explicitly
//! via the pidfile `wardn run` writes next to the vault.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const TEST_PORT: u16 = 27391;
const MAX_COST_TEST_PORT: u16 = 27392;

/// Kills the background daemon `wardn run` spawned, using the pidfile it
/// writes next to the vault. Best-effort — never panics on cleanup failure.
struct DaemonGuard {
    vault_dir: std::path::PathBuf,
    port: u16,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let pidfile = self
            .vault_dir
            .join(format!(".wardn-daemon-{}.pid", self.port));
        if let Ok(pid) = std::fs::read_to_string(&pidfile) {
            let pid = pid.trim();
            if !pid.is_empty() {
                let _ = std::process::Command::new("kill")
                    .args(["-9", pid])
                    .status();
            }
        }
        let _ = std::fs::remove_file(&pidfile);
    }
}

fn create_vault_with_key(dir: &Path, vault_path: &Path) {
    Command::cargo_bin("wardn")
        .unwrap()
        .current_dir(dir)
        .args(["--vault", vault_path.to_str().unwrap(), "vault", "create"])
        .env("WARDN_PASSPHRASE", "test-pass-1234")
        .assert()
        .success();

    Command::cargo_bin("wardn")
        .unwrap()
        .current_dir(dir)
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "vault",
            "set",
            "ANTHROPIC_KEY",
        ])
        .env("WARDN_PASSPHRASE", "test-pass-1234")
        .env("WARDN_VALUE", "sk-ant-real-key-e2e-test")
        .assert()
        .success();
}

#[test]
fn test_run_lazy_starts_daemon_and_wires_child_env() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("vault.enc");
    create_vault_with_key(dir.path(), &vault_path);

    let _guard = DaemonGuard {
        vault_dir: dir.path().to_path_buf(),
        port: TEST_PORT,
    };

    Command::cargo_bin("wardn")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "run",
            "--agent",
            "test-agent",
            "--host",
            "127.0.0.1",
            "--port",
            &TEST_PORT.to_string(),
            "--",
            "env",
        ])
        .env("WARDN_PASSPHRASE", "test-pass-1234")
        .timeout(std::time::Duration::from_secs(20))
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "ANTHROPIC_BASE_URL=http://127.0.0.1:{TEST_PORT}/anthropic"
        )))
        .stdout(predicate::str::contains(
            "ANTHROPIC_AUTH_TOKEN=wdn_placeholder_",
        ))
        .stdout(predicate::str::contains(
            "ANTHROPIC_API_KEY=wdn_placeholder_",
        ));

    // The real key must never appear in the child's environment dump.
    let output = Command::cargo_bin("wardn")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "run",
            "--agent",
            "test-agent",
            "--host",
            "127.0.0.1",
            "--port",
            &TEST_PORT.to_string(),
            "--",
            "env",
        ])
        .env("WARDN_PASSPHRASE", "test-pass-1234")
        .timeout(std::time::Duration::from_secs(20))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("sk-ant-real-key-e2e-test"));
}

#[test]
fn test_run_max_cost_sets_budget_visible_via_status() {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("vault.enc");
    create_vault_with_key(dir.path(), &vault_path);

    let _guard = DaemonGuard {
        vault_dir: dir.path().to_path_buf(),
        port: MAX_COST_TEST_PORT,
    };

    // `wardn run --max-cost` should set a real budget on the credential it
    // wires up — the same mechanism as `wardn budget set` — before
    // launching the child.
    Command::cargo_bin("wardn")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "run",
            "--agent",
            "test-agent",
            "--host",
            "127.0.0.1",
            "--port",
            &MAX_COST_TEST_PORT.to_string(),
            "--max-cost",
            "3.5",
            "--",
            "env",
        ])
        .env("WARDN_PASSPHRASE", "test-pass-1234")
        .timeout(std::time::Duration::from_secs(20))
        .assert()
        .success()
        .stderr(predicate::str::contains("capped"))
        .stderr(predicate::str::contains("$3.50"));

    // Query the (still-running, lazily-started) daemon for live budget
    // status and confirm the cap actually landed.
    Command::cargo_bin("wardn")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "--vault",
            vault_path.to_str().unwrap(),
            "budget",
            "status",
            "--agent",
            "test-agent",
            "--host",
            "127.0.0.1",
            "--port",
            &MAX_COST_TEST_PORT.to_string(),
        ])
        .env("WARDN_PASSPHRASE", "test-pass-1234")
        .timeout(std::time::Duration::from_secs(10))
        .assert()
        .success()
        .stdout(predicate::str::contains("ANTHROPIC_KEY"))
        .stdout(predicate::str::contains("$3.50"))
        .stdout(predicate::str::contains("hard"));
}
