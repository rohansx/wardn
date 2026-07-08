pub mod scanners;

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::vault::Vault;
use scanners::credentials::{self, FoundCredential, Severity};

/// Source system to scan and migrate from.
#[derive(Debug, Clone)]
pub enum MigrateSource {
    OpenClaw,
    ClaudeCode,
    Directory(PathBuf),
}

impl MigrateSource {
    pub fn default_path(&self) -> PathBuf {
        match self {
            MigrateSource::OpenClaw => {
                let home = std::env::var("HOME").unwrap_or_default();
                PathBuf::from(home).join(".openclaw")
            }
            MigrateSource::ClaudeCode => {
                let home = std::env::var("HOME").unwrap_or_default();
                PathBuf::from(home).join(".claude")
            }
            MigrateSource::Directory(p) => p.clone(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            MigrateSource::OpenClaw => "OpenClaw",
            MigrateSource::ClaudeCode => "Claude Code",
            MigrateSource::Directory(_) => "Directory",
        }
    }
}

/// Full security audit report.
#[derive(Debug, Serialize)]
pub struct MigrateReport {
    pub source: String,
    pub scan_path: String,
    pub credentials_found: Vec<FoundCredential>,
    pub total_critical: usize,
    pub total_high: usize,
    pub total_medium: usize,
    pub total_low: usize,
    pub migrated_count: usize,
    pub dry_run: bool,
}

impl MigrateReport {
    pub fn total_issues(&self) -> usize {
        self.credentials_found.len()
    }

    pub fn risk_score(&self) -> u32 {
        (self.total_critical * 40
            + self.total_high * 20
            + self.total_medium * 10
            + self.total_low * 5) as u32
    }

    /// Format as terminal output.
    pub fn to_terminal_string(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("\n  WARDN SECURITY AUDIT — {}\n", self.source));
        out.push_str(&format!("  Scanned: {}\n\n", self.scan_path));

        if self.credentials_found.is_empty() {
            out.push_str("  No exposed credentials found.\n\n");
            return out;
        }

        out.push_str(&format!(
            "  EXPOSED CREDENTIALS: {}\n",
            self.credentials_found.len()
        ));
        out.push_str(&format!(
            "  Risk Score: {}/100\n\n",
            self.risk_score().min(100)
        ));

        out.push_str("  Severity  | Name                  | Preview              | File\n");
        out.push_str("  ----------|----------------------|----------------------|-----\n");

        for cred in &self.credentials_found {
            let sev = match cred.severity {
                Severity::Critical => "CRITICAL",
                Severity::High => "HIGH    ",
                Severity::Medium => "MEDIUM  ",
                Severity::Low => "LOW     ",
            };
            out.push_str(&format!(
                "  {}| {:<21}| {:<21}| {}\n",
                sev, cred.name, cred.value_preview, cred.source_file
            ));
        }

        out.push('\n');

        if self.dry_run {
            out.push_str("  DRY RUN — no changes made. Run without --dry-run to migrate.\n");
        } else {
            out.push_str(&format!(
                "  Migrated {} credentials to encrypted Warden vault.\n",
                self.migrated_count
            ));
        }

        out.push('\n');
        out
    }
}

/// Run a migration scan. If `dry_run` is true, only audit — don't migrate.
pub fn run(
    source: &MigrateSource,
    vault: Option<&mut Vault>,
    dry_run: bool,
) -> crate::Result<MigrateReport> {
    run_with_path(source, &source.default_path(), vault, dry_run)
}

/// Run a migration scan against a specific path.
pub fn run_with_path(
    source: &MigrateSource,
    scan_path: &Path,
    vault: Option<&mut Vault>,
    dry_run: bool,
) -> crate::Result<MigrateReport> {
    let found = credentials::scan_directory(scan_path);

    let total_critical = found
        .iter()
        .filter(|c| c.severity == Severity::Critical)
        .count();
    let total_high = found
        .iter()
        .filter(|c| c.severity == Severity::High)
        .count();
    let total_medium = found
        .iter()
        .filter(|c| c.severity == Severity::Medium)
        .count();
    let total_low = found.iter().filter(|c| c.severity == Severity::Low).count();

    let mut migrated_count = 0;

    if !dry_run {
        if let Some(vault) = vault {
            for cred in &found {
                // cred.value carries the actual scanned value (never
                // serialized — see FoundCredential — so it doesn't leak
                // into the dry-run report/JSON export, only into the vault).
                let _ = vault.set(&cred.name, &cred.value);
                migrated_count += 1;
            }
        }
    }

    Ok(MigrateReport {
        source: source.name().to_string(),
        scan_path: scan_path.display().to_string(),
        credentials_found: found,
        total_critical,
        total_high,
        total_medium,
        total_low,
        migrated_count,
        dry_run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "OPENAI_KEY=sk-proj-abc123def456ghi789\nANTHROPIC_KEY=sk-ant-xyz789abc123def456\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            "[api]\nkey = \"ghp_1234567890abcdef1234567890abcdef12345678\"\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn test_dry_run_finds_credentials() {
        let dir = setup_test_dir();
        let source = MigrateSource::Directory(dir.path().to_path_buf());
        let report = run_with_path(&source, dir.path(), None, true).unwrap();

        assert!(report.total_issues() >= 2);
        assert!(report.total_critical >= 1);
        assert!(report.dry_run);
        assert_eq!(report.migrated_count, 0);
    }

    #[test]
    fn test_migration_stores_to_vault() {
        let dir = setup_test_dir();
        let mut vault = Vault::ephemeral();
        let source = MigrateSource::Directory(dir.path().to_path_buf());

        let report = run_with_path(&source, dir.path(), Some(&mut vault), false).unwrap();

        assert!(!report.dry_run);
        assert!(report.migrated_count > 0);
        assert!(!vault.is_empty());
    }

    #[test]
    fn test_migration_stores_the_real_scanned_value_not_a_marker() {
        let dir = setup_test_dir();
        let mut vault = Vault::ephemeral();
        let source = MigrateSource::Directory(dir.path().to_path_buf());

        run_with_path(&source, dir.path(), Some(&mut vault), false).unwrap();

        let openai = vault.get("OPENAI_KEY").unwrap().expose();
        assert_eq!(openai, "sk-proj-abc123def456ghi789");
        assert!(!openai.contains("MIGRATED"));

        let anthropic = vault.get("ANTHROPIC_KEY").unwrap().expose();
        assert_eq!(anthropic, "sk-ant-xyz789abc123def456");
    }

    #[test]
    fn test_risk_score() {
        let dir = setup_test_dir();
        let source = MigrateSource::Directory(dir.path().to_path_buf());
        let report = run_with_path(&source, dir.path(), None, true).unwrap();

        assert!(report.risk_score() > 0);
    }

    #[test]
    fn test_terminal_output_no_leaks() {
        let dir = setup_test_dir();
        let source = MigrateSource::Directory(dir.path().to_path_buf());
        let report = run_with_path(&source, dir.path(), None, true).unwrap();

        let output = report.to_terminal_string();
        // Should not contain full credential values
        assert!(!output.contains("sk-proj-abc123def456ghi789"));
        assert!(!output.contains("sk-ant-xyz789abc123def456"));
        // Should contain truncated previews
        assert!(output.contains("..."));
    }

    #[test]
    fn test_empty_directory() {
        let dir = TempDir::new().unwrap();
        let source = MigrateSource::Directory(dir.path().to_path_buf());
        let report = run_with_path(&source, dir.path(), None, true).unwrap();

        assert_eq!(report.total_issues(), 0);
        assert_eq!(report.risk_score(), 0);
    }

    #[test]
    fn test_report_json_export() {
        let dir = setup_test_dir();
        let source = MigrateSource::Directory(dir.path().to_path_buf());
        let report = run_with_path(&source, dir.path(), None, true).unwrap();

        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("credentials_found"));
        assert!(json.contains("total_critical"));
    }

    #[test]
    fn test_report_json_export_never_contains_real_scanned_values() {
        // FoundCredential.value carries the real value so migrate can store
        // it — it must never leak into the report/JSON, even though the
        // dry-run report DOES include the redacted value_preview.
        let dir = setup_test_dir();
        let source = MigrateSource::Directory(dir.path().to_path_buf());
        let report = run_with_path(&source, dir.path(), None, true).unwrap();

        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(!json.contains("sk-proj-abc123def456ghi789"));
        assert!(!json.contains("sk-ant-xyz789abc123def456"));
        assert!(!json.contains("ghp_1234567890abcdef1234567890abcdef12345678"));
        // The redacted preview form is still present.
        assert!(json.contains("value_preview"));
    }

    #[test]
    fn test_source_names() {
        assert_eq!(MigrateSource::OpenClaw.name(), "OpenClaw");
        assert_eq!(MigrateSource::ClaudeCode.name(), "Claude Code");
    }
}
