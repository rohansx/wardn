use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Maximum number of audit entries retained in the ring buffer.
/// Sized to comfortably back a dashboard polling every ~2s for ~15 minutes
/// of activity; older events remain visible in stderr logs.
pub const DEFAULT_AUDIT_CAPACITY: usize = 500;

/// A single audit event tracked for the local dashboard.
///
/// `event` is one of:
///   - "request_completed" — proxy successfully forwarded a request.
///   - "credential_injected" — a placeholder was swapped for a real key.
///   - "credential_stripped" — a real key was rewritten back to placeholder
///     in a response.
///   - "rate_limit"          — agent hit a per-credential rate limit.
///   - "budget_exceeded"     — agent hit a per-credential budget cap.
///   - "loop_detected"       — repeated request fingerprint tripped loop guard.
///   - "domain_denied"       — credential used against a disallowed domain.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub agent: String,
    pub event: String,
    pub credential: Option<String>,
    pub method: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub cost_usd: Option<f64>,
}

impl AuditEntry {
    pub fn new(request_id: impl Into<String>, agent: impl Into<String>, event: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            request_id: request_id.into(),
            agent: agent.into(),
            event: event.into(),
            credential: None,
            method: None,
            domain: None,
            path: None,
            status: None,
            cost_usd: None,
        }
    }

    pub fn credential(mut self, name: impl Into<String>) -> Self {
        self.credential = Some(name.into());
        self
    }

    pub fn request(mut self, method: impl Into<String>, domain: impl Into<String>, path: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self.domain = Some(domain.into());
        self.path = Some(path.into());
        self
    }

    pub fn status(mut self, code: u16) -> Self {
        self.status = Some(code);
        self
    }

    pub fn cost(mut self, usd: f64) -> Self {
        self.cost_usd = Some(usd);
        self
    }
}

/// Bounded audit log. Newest entries at the back, oldest at the front;
/// once at capacity, pushing a new entry drops the oldest.
/// Lock contention is fine for the dashboard's ~2s polling cadence.
#[derive(Debug)]
pub struct AuditLog {
    capacity: usize,
    entries: VecDeque<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_AUDIT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: VecDeque::with_capacity(capacity),
        }
    }

    pub fn record(&mut self, entry: AuditEntry) {
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Returns entries newest-first, capped to `limit`.
    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let take = limit.min(self.entries.len());
        self.entries.iter().rev().take(take).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared handle for proxy + dashboard routes.
pub type SharedAuditLog = Arc<Mutex<AuditLog>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_recent_newest_first() {
        let mut log = AuditLog::with_capacity(3);
        log.record(AuditEntry::new("r1", "agent", "request_completed"));
        log.record(AuditEntry::new("r2", "agent", "request_completed"));
        log.record(AuditEntry::new("r3", "agent", "request_completed"));

        let recent = log.recent(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].request_id, "r3");
        assert_eq!(recent[1].request_id, "r2");
        assert_eq!(recent[2].request_id, "r1");
    }

    #[test]
    fn test_respects_capacity_evicts_oldest() {
        let mut log = AuditLog::with_capacity(2);
        log.record(AuditEntry::new("r1", "agent", "e"));
        log.record(AuditEntry::new("r2", "agent", "e"));
        log.record(AuditEntry::new("r3", "agent", "e"));
        assert_eq!(log.len(), 2);
        let recent = log.recent(10);
        assert_eq!(recent[0].request_id, "r3");
        assert_eq!(recent[1].request_id, "r2");
    }

    #[test]
    fn test_recent_limit_caps_output() {
        let mut log = AuditLog::with_capacity(10);
        for i in 0..5 {
            log.record(AuditEntry::new(format!("r{i}"), "agent", "e"));
        }
        let recent = log.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].request_id, "r4");
        assert_eq!(recent[1].request_id, "r3");
    }

    #[test]
    fn test_builder_chain() {
        let entry = AuditEntry::new("rid", "agent", "request_completed")
            .credential("OPENAI_KEY")
            .request("POST", "api.openai.com", "/v1/chat/completions")
            .status(200)
            .cost(0.000123);

        assert_eq!(entry.credential.as_deref(), Some("OPENAI_KEY"));
        assert_eq!(entry.method.as_deref(), Some("POST"));
        assert_eq!(entry.domain.as_deref(), Some("api.openai.com"));
        assert_eq!(entry.status, Some(200));
        assert!(entry.cost_usd.unwrap() > 0.0);
    }

    #[test]
    fn test_zero_capacity_clamps_to_one() {
        let log = AuditLog::with_capacity(0);
        assert_eq!(log.capacity(), 1);
    }
}
