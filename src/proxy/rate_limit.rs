use std::collections::HashMap;
use std::time::Instant;

use crate::config::RateLimitConfig;

/// Status info for a rate limit bucket (safe to expose).
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    pub remaining: u32,
    pub limit: u32,
    pub period_seconds: u64,
    pub retry_after_seconds: Option<u64>,
}

/// Token bucket rate limiter keyed by (credential, agent).
pub struct RateLimiter {
    buckets: HashMap<(String, String), TokenBucket>,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
    period_seconds: u64,
}

impl TokenBucket {
    fn new(config: &RateLimitConfig) -> Self {
        let period_seconds = config.per.as_seconds();
        let refill_rate = config.max_calls as f64 / period_seconds as f64;
        Self {
            tokens: config.max_calls as f64,
            max_tokens: config.max_calls as f64,
            refill_rate,
            last_refill: Instant::now(),
            period_seconds,
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn try_consume(&mut self) -> Result<(), u64> {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate seconds until 1 token is available
            let deficit = 1.0 - self.tokens;
            let retry_after = (deficit / self.refill_rate).ceil() as u64;
            Err(retry_after.max(1))
        }
    }

    fn status(&mut self) -> RateLimitStatus {
        self.refill();
        let remaining = self.tokens.floor() as u32;
        let retry_after = if self.tokens < 1.0 {
            let deficit = 1.0 - self.tokens;
            Some((deficit / self.refill_rate).ceil() as u64)
        } else {
            None
        };
        RateLimitStatus {
            remaining,
            limit: self.max_tokens as u32,
            period_seconds: self.period_seconds,
            retry_after_seconds: retry_after,
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    /// Configure a rate limit for a (credential, agent) pair.
    pub fn configure(&mut self, credential: &str, agent: &str, config: &RateLimitConfig) {
        let key = (credential.to_string(), agent.to_string());
        self.buckets.insert(key, TokenBucket::new(config));
    }

    /// Check and consume one token. Returns `Ok(())` if allowed,
    /// `Err(retry_after_seconds)` if rate limited.
    pub fn check(&mut self, credential: &str, agent: &str) -> Result<(), u64> {
        let key = (credential.to_string(), agent.to_string());
        match self.buckets.get_mut(&key) {
            Some(bucket) => bucket.try_consume(),
            None => Ok(()), // no rate limit configured = unlimited
        }
    }

    /// Get current status for a (credential, agent) pair.
    pub fn status(&mut self, credential: &str, agent: &str) -> Option<RateLimitStatus> {
        let key = (credential.to_string(), agent.to_string());
        self.buckets.get_mut(&key).map(|b| b.status())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TimePeriod;

    fn config_200_per_hour() -> RateLimitConfig {
        RateLimitConfig {
            max_calls: 200,
            per: TimePeriod::Hour,
        }
    }

    fn config_5_per_second() -> RateLimitConfig {
        RateLimitConfig {
            max_calls: 5,
            per: TimePeriod::Second,
        }
    }

    #[test]
    fn test_allows_within_limit() {
        let mut rl = RateLimiter::new();
        rl.configure("KEY", "agent", &config_200_per_hour());

        for _ in 0..5 {
            assert!(rl.check("KEY", "agent").is_ok());
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let mut rl = RateLimiter::new();
        rl.configure("KEY", "agent", &config_5_per_second());

        // Exhaust all 5 tokens
        for _ in 0..5 {
            assert!(rl.check("KEY", "agent").is_ok());
        }

        // 6th call should be blocked
        let result = rl.check("KEY", "agent");
        assert!(result.is_err());
        let retry_after = result.unwrap_err();
        assert!(
            retry_after >= 1,
            "retry_after should be >= 1, got {retry_after}"
        );
    }

    #[test]
    fn test_retry_after_calculation() {
        let mut rl = RateLimiter::new();
        rl.configure("KEY", "agent", &config_200_per_hour());

        // Exhaust all tokens
        for _ in 0..200 {
            let _ = rl.check("KEY", "agent");
        }

        let retry = rl.check("KEY", "agent").unwrap_err();
        // Should need to wait some seconds for 1 token to refill
        // 200 per 3600s = 1 token per 18s
        assert!(retry >= 1);
        assert!(retry <= 20, "retry_after should be ~18s, got {retry}");
    }

    #[test]
    fn test_independent_per_agent() {
        let mut rl = RateLimiter::new();
        rl.configure("KEY", "agent-a", &config_5_per_second());
        rl.configure("KEY", "agent-b", &config_5_per_second());

        // Exhaust agent-a
        for _ in 0..5 {
            assert!(rl.check("KEY", "agent-a").is_ok());
        }
        assert!(rl.check("KEY", "agent-a").is_err());

        // agent-b should still work
        assert!(rl.check("KEY", "agent-b").is_ok());
    }

    #[test]
    fn test_independent_per_credential() {
        let mut rl = RateLimiter::new();
        rl.configure("KEY_A", "agent", &config_5_per_second());
        rl.configure("KEY_B", "agent", &config_5_per_second());

        // Exhaust KEY_A
        for _ in 0..5 {
            assert!(rl.check("KEY_A", "agent").is_ok());
        }
        assert!(rl.check("KEY_A", "agent").is_err());

        // KEY_B should still work
        assert!(rl.check("KEY_B", "agent").is_ok());
    }

    #[test]
    fn test_no_config_means_unlimited() {
        let mut rl = RateLimiter::new();
        // No configure call
        for _ in 0..1000 {
            assert!(rl.check("KEY", "agent").is_ok());
        }
    }

    #[test]
    fn test_status_shows_remaining() {
        let mut rl = RateLimiter::new();
        rl.configure("KEY", "agent", &config_5_per_second());

        let status = rl.status("KEY", "agent").unwrap();
        assert_eq!(status.limit, 5);
        assert_eq!(status.remaining, 5);
        assert!(status.retry_after_seconds.is_none());

        // Consume 3
        for _ in 0..3 {
            rl.check("KEY", "agent").unwrap();
        }

        let status = rl.status("KEY", "agent").unwrap();
        assert_eq!(status.remaining, 2);
    }

    #[test]
    fn test_status_unconfigured_returns_none() {
        let mut rl = RateLimiter::new();
        assert!(rl.status("KEY", "agent").is_none());
    }

    #[test]
    fn test_status_shows_retry_after_when_exhausted() {
        let mut rl = RateLimiter::new();
        rl.configure("KEY", "agent", &config_5_per_second());

        for _ in 0..5 {
            rl.check("KEY", "agent").unwrap();
        }

        let status = rl.status("KEY", "agent").unwrap();
        assert_eq!(status.remaining, 0);
        assert!(status.retry_after_seconds.is_some());
    }
}
