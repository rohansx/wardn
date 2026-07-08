use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

/// Detects tight retry loops: the identical request (by fingerprint)
/// repeated many times in a short window, for the same agent.
///
/// This is a distinct, earlier line of defense than dollar budgets — it
/// catches a stuck retry loop before it has spent enough to hit a budget
/// cap, which matters most for agents with no budget configured at all (or
/// a generous one that a tight loop could still burn through before the
/// window resets).
pub struct LoopGuard {
    window: Duration,
    max_repeats: usize,
    // agent -> fingerprint -> recent timestamps
    history: HashMap<String, HashMap<u64, VecDeque<Instant>>>,
}

pub struct LoopGuardConfig {
    pub window: Duration,
    pub max_repeats: usize,
}

impl Default for LoopGuardConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            max_repeats: 5,
        }
    }
}

/// Fingerprint a request by method + domain + path + body. Two requests
/// with the same fingerprint are, for loop-detection purposes, "the same
/// request retried" — the exact scenario a stuck agent produces.
pub fn fingerprint(method: &str, domain: &str, path: &str, body: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    method.hash(&mut hasher);
    domain.hash(&mut hasher);
    path.hash(&mut hasher);
    body.hash(&mut hasher);
    hasher.finish()
}

impl LoopGuard {
    pub fn new(config: LoopGuardConfig) -> Self {
        Self {
            window: config.window,
            max_repeats: config.max_repeats,
            history: HashMap::new(),
        }
    }

    /// Record a request and check whether it trips the loop threshold.
    /// Returns `Some(repeat_count)` once this agent has repeated the
    /// identical request `max_repeats` or more times within `window`.
    pub fn record_and_check(&mut self, agent_id: &str, fingerprint: u64) -> Option<usize> {
        let now = Instant::now();
        let window = self.window;
        let max_repeats = self.max_repeats;

        let timestamps = self
            .history
            .entry(agent_id.to_string())
            .or_default()
            .entry(fingerprint)
            .or_default();

        while let Some(&front) = timestamps.front() {
            if now.duration_since(front) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        timestamps.push_back(now);
        let count = timestamps.len();

        if count >= max_repeats {
            Some(count)
        } else {
            None
        }
    }
}

impl Default for LoopGuard {
    fn default() -> Self {
        Self::new(LoopGuardConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_is_stable_for_same_input() {
        let a = fingerprint("POST", "api.example.com", "/v1/x", b"body");
        let b = fingerprint("POST", "api.example.com", "/v1/x", b"body");
        assert_eq!(a, b);
    }

    #[test]
    fn test_fingerprint_differs_for_different_body() {
        let a = fingerprint("POST", "api.example.com", "/v1/x", b"body-a");
        let b = fingerprint("POST", "api.example.com", "/v1/x", b"body-b");
        assert_ne!(a, b);
    }

    #[test]
    fn test_fingerprint_differs_for_different_path() {
        let a = fingerprint("POST", "api.example.com", "/v1/a", b"body");
        let b = fingerprint("POST", "api.example.com", "/v1/b", b"body");
        assert_ne!(a, b);
    }

    fn guard(max_repeats: usize) -> LoopGuard {
        LoopGuard::new(LoopGuardConfig {
            window: Duration::from_secs(10),
            max_repeats,
        })
    }

    #[test]
    fn test_below_threshold_does_not_trip() {
        let mut g = guard(5);
        let fp = fingerprint("POST", "api.example.com", "/x", b"body");
        for _ in 0..4 {
            assert!(g.record_and_check("agent", fp).is_none());
        }
    }

    #[test]
    fn test_at_threshold_trips() {
        let mut g = guard(5);
        let fp = fingerprint("POST", "api.example.com", "/x", b"body");
        for _ in 0..4 {
            assert!(g.record_and_check("agent", fp).is_none());
        }
        let result = g.record_and_check("agent", fp);
        assert_eq!(result, Some(5));
    }

    #[test]
    fn test_different_fingerprints_do_not_accumulate_together() {
        // A genuinely varied workload (different requests each time) must
        // never trip the guard, no matter how many requests are made.
        let mut g = guard(3);
        for i in 0..10 {
            let fp = fingerprint(
                "POST",
                "api.example.com",
                "/x",
                format!("body-{i}").as_bytes(),
            );
            assert!(g.record_and_check("agent", fp).is_none());
        }
    }

    #[test]
    fn test_independent_per_agent() {
        let mut g = guard(3);
        let fp = fingerprint("POST", "api.example.com", "/x", b"body");
        g.record_and_check("agent-a", fp);
        g.record_and_check("agent-a", fp);
        let a_result = g.record_and_check("agent-a", fp);
        assert_eq!(a_result, Some(3));

        // agent-b's identical requests are tracked independently.
        assert!(g.record_and_check("agent-b", fp).is_none());
    }

    #[test]
    fn test_old_entries_outside_window_are_pruned() {
        // A guard with a zero-length window means every request is
        // "outside the window" of the previous one by the time it's
        // checked, so the count effectively never accumulates past 1.
        let mut g = LoopGuard::new(LoopGuardConfig {
            window: Duration::from_nanos(1),
            max_repeats: 3,
        });
        let fp = fingerprint("POST", "api.example.com", "/x", b"body");
        std::thread::sleep(Duration::from_millis(2));
        assert!(g.record_and_check("agent", fp).is_none());
        std::thread::sleep(Duration::from_millis(2));
        assert!(g.record_and_check("agent", fp).is_none());
    }
}
