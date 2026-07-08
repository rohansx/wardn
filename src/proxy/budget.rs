use std::collections::HashMap;
use std::time::Instant;

use crate::config::{BudgetConfig, BudgetMode, BudgetWindow};

/// Snapshot of a budget bucket's state, safe to expose (e.g. `wardn budget
/// status`, `check_rate_limit`-style MCP responses).
#[derive(Debug, Clone, Copy)]
pub struct BudgetStatus {
    pub spent_usd: f64,
    pub max_usd: f64,
    pub remaining_usd: f64,
    pub mode: BudgetMode,
    pub window: BudgetWindow,
}

/// Result of a pre-flight budget check, before a request is forwarded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BudgetCheck {
    /// Within budget, or no budget configured (unlimited).
    Ok,
    /// Hard-mode budget already exceeded — the caller must block.
    Exceeded { spent_usd: f64, max_usd: f64 },
    /// Soft-mode budget already exceeded — the caller may still allow the
    /// request, but should log/flag it.
    ExceededSoft { spent_usd: f64, max_usd: f64 },
}

impl BudgetCheck {
    pub fn is_blocking(&self) -> bool {
        matches!(self, BudgetCheck::Exceeded { .. })
    }
}

/// Whether a window that started `elapsed_secs` ago has expired and should
/// reset. Pure/time-free so it's directly unit-testable without sleeping.
fn window_expired(elapsed_secs: u64, window: BudgetWindow) -> bool {
    match window.as_seconds() {
        Some(window_secs) => elapsed_secs >= window_secs,
        None => false, // Total never resets
    }
}

struct BudgetBucket {
    spent_usd: f64,
    window_start: Instant,
    config: BudgetConfig,
}

impl BudgetBucket {
    fn new(config: BudgetConfig) -> Self {
        Self {
            spent_usd: 0.0,
            window_start: Instant::now(),
            config,
        }
    }

    fn maybe_reset(&mut self) {
        if window_expired(self.window_start.elapsed().as_secs(), self.config.window) {
            self.spent_usd = 0.0;
            self.window_start = Instant::now();
        }
    }

    fn is_exceeded(&mut self) -> bool {
        self.maybe_reset();
        self.spent_usd >= self.config.max_usd
    }

    fn record_spend(&mut self, usd: f64) {
        self.maybe_reset();
        self.spent_usd += usd;
    }

    fn status(&mut self) -> BudgetStatus {
        self.maybe_reset();
        BudgetStatus {
            spent_usd: self.spent_usd,
            max_usd: self.config.max_usd,
            remaining_usd: (self.config.max_usd - self.spent_usd).max(0.0),
            mode: self.config.mode,
            window: self.config.window,
        }
    }
}

/// Tracks dollar spend per (credential, agent), mirroring `RateLimiter`'s
/// bucket-per-pair model. Unconfigured pairs are unlimited — same "empty =
/// allow all" convention used throughout the vault/config layer.
pub struct BudgetTracker {
    buckets: HashMap<(String, String), BudgetBucket>,
}

impl BudgetTracker {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    pub fn configure(&mut self, credential: &str, agent: &str, config: &BudgetConfig) {
        let key = (credential.to_string(), agent.to_string());
        self.buckets.insert(key, BudgetBucket::new(*config));
    }

    /// Ensure a bucket exists for (credential, agent), creating one from
    /// `config` if missing. If a bucket already exists, its config is
    /// updated in place (so a live `wardn budget set` change takes effect
    /// immediately) but accumulated spend/window state is preserved —
    /// changing the cap doesn't secretly reset what's already been spent.
    pub fn ensure_configured(&mut self, credential: &str, agent: &str, config: BudgetConfig) {
        let key = (credential.to_string(), agent.to_string());
        match self.buckets.get_mut(&key) {
            Some(bucket) => bucket.config = config,
            None => {
                self.buckets.insert(key, BudgetBucket::new(config));
            }
        }
    }

    /// Pre-flight check before forwarding a request. Only `Exceeded` (hard
    /// mode) should actually block — `ExceededSoft` is informational.
    pub fn check(&mut self, credential: &str, agent: &str) -> BudgetCheck {
        let key = (credential.to_string(), agent.to_string());
        let Some(bucket) = self.buckets.get_mut(&key) else {
            return BudgetCheck::Ok;
        };

        if !bucket.is_exceeded() {
            return BudgetCheck::Ok;
        }

        match bucket.config.mode {
            BudgetMode::Hard => BudgetCheck::Exceeded {
                spent_usd: bucket.spent_usd,
                max_usd: bucket.config.max_usd,
            },
            BudgetMode::Soft => BudgetCheck::ExceededSoft {
                spent_usd: bucket.spent_usd,
                max_usd: bucket.config.max_usd,
            },
        }
    }

    /// Record actual spend after a response's cost is known. A no-op if
    /// this (credential, agent) pair has no budget configured.
    pub fn record_spend(&mut self, credential: &str, agent: &str, usd: f64) {
        let key = (credential.to_string(), agent.to_string());
        if let Some(bucket) = self.buckets.get_mut(&key) {
            bucket.record_spend(usd);
        }
    }

    pub fn status(&mut self, credential: &str, agent: &str) -> Option<BudgetStatus> {
        let key = (credential.to_string(), agent.to_string());
        self.buckets.get_mut(&key).map(BudgetBucket::status)
    }
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hard_budget(max_usd: f64) -> BudgetConfig {
        BudgetConfig {
            max_usd,
            window: BudgetWindow::Day,
            mode: BudgetMode::Hard,
        }
    }

    fn soft_budget(max_usd: f64) -> BudgetConfig {
        BudgetConfig {
            max_usd,
            window: BudgetWindow::Day,
            mode: BudgetMode::Soft,
        }
    }

    #[test]
    fn test_window_expired_pure_logic() {
        assert!(!window_expired(100, BudgetWindow::Day)); // 100s < 86400s
        assert!(window_expired(90_000, BudgetWindow::Day)); // > 86400s
        assert!(!window_expired(u64::MAX, BudgetWindow::Total)); // never
    }

    #[test]
    fn test_unconfigured_pair_is_unlimited() {
        let mut t = BudgetTracker::new();
        assert_eq!(t.check("KEY", "agent"), BudgetCheck::Ok);
        assert!(t.status("KEY", "agent").is_none());
    }

    #[test]
    fn test_spend_within_budget_is_ok() {
        let mut t = BudgetTracker::new();
        t.configure("KEY", "agent", &hard_budget(10.0));
        t.record_spend("KEY", "agent", 3.0);
        assert_eq!(t.check("KEY", "agent"), BudgetCheck::Ok);

        let status = t.status("KEY", "agent").unwrap();
        assert_eq!(status.spent_usd, 3.0);
        assert_eq!(status.remaining_usd, 7.0);
    }

    #[test]
    fn test_hard_budget_blocks_once_exceeded() {
        let mut t = BudgetTracker::new();
        t.configure("KEY", "agent", &hard_budget(5.0));
        t.record_spend("KEY", "agent", 5.5);

        let check = t.check("KEY", "agent");
        assert!(check.is_blocking());
        assert_eq!(
            check,
            BudgetCheck::Exceeded {
                spent_usd: 5.5,
                max_usd: 5.0
            }
        );
    }

    #[test]
    fn test_soft_budget_flags_but_does_not_block() {
        let mut t = BudgetTracker::new();
        t.configure("KEY", "agent", &soft_budget(5.0));
        t.record_spend("KEY", "agent", 5.5);

        let check = t.check("KEY", "agent");
        assert!(!check.is_blocking());
        assert_eq!(
            check,
            BudgetCheck::ExceededSoft {
                spent_usd: 5.5,
                max_usd: 5.0
            }
        );
    }

    #[test]
    fn test_exactly_at_limit_counts_as_exceeded() {
        let mut t = BudgetTracker::new();
        t.configure("KEY", "agent", &hard_budget(5.0));
        t.record_spend("KEY", "agent", 5.0);
        assert!(t.check("KEY", "agent").is_blocking());
    }

    #[test]
    fn test_independent_per_agent() {
        let mut t = BudgetTracker::new();
        t.configure("KEY", "agent-a", &hard_budget(5.0));
        t.configure("KEY", "agent-b", &hard_budget(5.0));
        t.record_spend("KEY", "agent-a", 10.0);

        assert!(t.check("KEY", "agent-a").is_blocking());
        assert_eq!(t.check("KEY", "agent-b"), BudgetCheck::Ok);
    }

    #[test]
    fn test_independent_per_credential() {
        let mut t = BudgetTracker::new();
        t.configure("KEY_A", "agent", &hard_budget(5.0));
        t.configure("KEY_B", "agent", &hard_budget(5.0));
        t.record_spend("KEY_A", "agent", 10.0);

        assert!(t.check("KEY_A", "agent").is_blocking());
        assert_eq!(t.check("KEY_B", "agent"), BudgetCheck::Ok);
    }

    #[test]
    fn test_record_spend_on_unconfigured_pair_is_noop() {
        let mut t = BudgetTracker::new();
        // No configure() call — must not panic, must stay unlimited.
        t.record_spend("KEY", "agent", 1_000_000.0);
        assert_eq!(t.check("KEY", "agent"), BudgetCheck::Ok);
    }

    #[test]
    fn test_status_reports_remaining_never_negative() {
        let mut t = BudgetTracker::new();
        t.configure("KEY", "agent", &hard_budget(5.0));
        t.record_spend("KEY", "agent", 12.0); // way over
        let status = t.status("KEY", "agent").unwrap();
        assert_eq!(status.remaining_usd, 0.0); // not negative
        assert_eq!(status.spent_usd, 12.0); // but spend itself isn't clamped
    }

    #[test]
    fn test_ensure_configured_creates_bucket_when_missing() {
        let mut t = BudgetTracker::new();
        assert!(t.status("KEY", "agent").is_none());
        t.ensure_configured("KEY", "agent", hard_budget(5.0));
        assert_eq!(t.status("KEY", "agent").unwrap().max_usd, 5.0);
    }

    #[test]
    fn test_ensure_configured_updates_cap_but_preserves_spend() {
        let mut t = BudgetTracker::new();
        t.configure("KEY", "agent", &hard_budget(5.0));
        t.record_spend("KEY", "agent", 3.0);

        // Simulate `wardn budget set` raising the cap.
        t.ensure_configured("KEY", "agent", hard_budget(20.0));

        let status = t.status("KEY", "agent").unwrap();
        assert_eq!(status.max_usd, 20.0);
        assert_eq!(status.spent_usd, 3.0, "existing spend must not reset");
    }

    #[test]
    fn test_accumulates_multiple_spends() {
        let mut t = BudgetTracker::new();
        t.configure("KEY", "agent", &hard_budget(10.0));
        t.record_spend("KEY", "agent", 2.0);
        t.record_spend("KEY", "agent", 3.0);
        t.record_spend("KEY", "agent", 1.5);
        assert_eq!(t.status("KEY", "agent").unwrap().spent_usd, 6.5);
    }
}
