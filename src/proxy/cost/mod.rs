pub mod pricing;

use serde_json::Value;

/// Token counts for a single request/response, used to estimate spend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl TokenUsage {
    pub fn total(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

/// Extract token usage from a non-streaming JSON response body, trying both
/// dominant shapes:
///  - OpenAI-style: `usage.prompt_tokens` / `usage.completion_tokens`
///  - Anthropic-style: `usage.input_tokens` / `usage.output_tokens`
pub fn extract_usage_from_json(body: &[u8]) -> Option<TokenUsage> {
    let value: Value = serde_json::from_slice(body).ok()?;
    extract_usage_from_value(&value)
}

fn extract_usage_from_value(value: &Value) -> Option<TokenUsage> {
    let usage = value.get("usage")?;

    // Each pair only needs ONE side present — Anthropic's `message_delta`
    // events, for example, carry `usage.output_tokens` alone (no
    // `input_tokens`, since that was already reported in `message_start`).
    let openai_input = usage.get("prompt_tokens").and_then(Value::as_u64);
    let openai_output = usage.get("completion_tokens").and_then(Value::as_u64);
    if openai_input.is_some() || openai_output.is_some() {
        return Some(TokenUsage {
            input_tokens: openai_input.unwrap_or(0),
            output_tokens: openai_output.unwrap_or(0),
        });
    }

    let input = usage.get("input_tokens").and_then(Value::as_u64);
    let output = usage.get("output_tokens").and_then(Value::as_u64);
    if input.is_some() || output.is_some() {
        return Some(TokenUsage {
            input_tokens: input.unwrap_or(0),
            output_tokens: output.unwrap_or(0),
        });
    }

    None
}

/// Extract usage from a single SSE `data: {...}` event payload (the JSON
/// body only, without the `data: ` prefix). Handles the two dominant
/// streaming shapes:
///  - Anthropic Messages API: `message_start` carries initial
///    `message.usage.input_tokens` (+ a starting `output_tokens`, usually 0);
///    `message_delta` carries the cumulative `usage.output_tokens`.
///  - OpenAI Chat Completions streaming: the final chunk carries a
///    top-level `usage` object when the caller requested
///    `stream_options.include_usage`.
///
/// Returns `None` for events that carry no usage info at all (most
/// streamed token deltas) — that's expected and not an error.
pub fn extract_usage_from_sse_event(event_json: &str) -> Option<TokenUsage> {
    let value: Value = serde_json::from_str(event_json).ok()?;

    if let Some(message_usage) = value.get("message").and_then(|m| m.get("usage")) {
        let input = message_usage
            .get("input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let output = message_usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        return Some(TokenUsage {
            input_tokens: input,
            output_tokens: output,
        });
    }

    extract_usage_from_value(&value)
}

/// Extract a `model` field from a JSON request or response body — the same
/// top-level key is used by both OpenAI and Anthropic on both sides.
pub fn extract_model_from_json(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value.get("model").and_then(Value::as_str).map(String::from)
}

/// Accumulates usage across a stream of SSE events. Streaming APIs report
/// usage incrementally (input tokens up front, output tokens as a running
/// total in later events) — later present values win over earlier ones,
/// which converges on the final cumulative totals.
#[derive(Debug, Clone, Copy, Default)]
pub struct UsageAccumulator {
    usage: TokenUsage,
}

impl UsageAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_sse_event(&mut self, event_json: &str) {
        if let Some(u) = extract_usage_from_sse_event(event_json) {
            if u.input_tokens > 0 {
                self.usage.input_tokens = u.input_tokens;
            }
            if u.output_tokens > 0 {
                self.usage.output_tokens = u.output_tokens;
            }
        }
    }

    pub fn usage(&self) -> TokenUsage {
        self.usage
    }
}

/// Parse a raw SSE response body (possibly truncated — see the cost-tap cap
/// in `proxy::mod`) for `data: {...}` events and return the accumulated
/// usage, or `None` if no event carried usage info at all.
pub fn sse_usage_from_bytes(body: &[u8]) -> Option<TokenUsage> {
    let text = std::str::from_utf8(body).ok()?;
    let mut acc = UsageAccumulator::new();

    for line in text.lines() {
        let Some(payload) = line
            .strip_prefix("data: ")
            .or_else(|| line.strip_prefix("data:"))
        else {
            continue;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        acc.observe_sse_event(payload);
    }

    let usage = acc.usage();
    if usage.total() > 0 {
        Some(usage)
    } else {
        None
    }
}

/// Rough fallback token estimate for responses that never report usage at
/// all. ~4 bytes/token is a standard, deliberately conservative rule of
/// thumb for English text. This exists so budget enforcement degrades to an
/// estimate instead of silently charging nothing — a provider/model that
/// doesn't report usage must not become a free way around a budget cap.
const FALLBACK_BYTES_PER_TOKEN: usize = 4;

pub fn estimate_tokens_from_bytes(len: usize) -> u64 {
    ((len / FALLBACK_BYTES_PER_TOKEN).max(if len > 0 { 1 } else { 0 })) as u64
}

/// Estimate USD cost for a given provider/model and token usage.
pub fn estimate_cost_usd(provider_slug: &str, model: &str, usage: TokenUsage) -> f64 {
    let p = pricing::lookup(provider_slug, model);
    (usage.input_tokens as f64 / 1_000_000.0) * p.input_per_million
        + (usage.output_tokens as f64 / 1_000_000.0) * p.output_per_million
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_openai_style_usage() {
        let body = br#"{"id":"x","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}"#;
        let usage = extract_usage_from_json(body).unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    #[test]
    fn test_extract_anthropic_style_usage() {
        let body = br#"{"id":"x","model":"claude-sonnet-5","usage":{"input_tokens":200,"output_tokens":80}}"#;
        let usage = extract_usage_from_json(body).unwrap();
        assert_eq!(usage.input_tokens, 200);
        assert_eq!(usage.output_tokens, 80);
    }

    #[test]
    fn test_extract_usage_missing_returns_none() {
        let body = br#"{"id":"x","choices":[]}"#;
        assert!(extract_usage_from_json(body).is_none());
    }

    #[test]
    fn test_extract_usage_from_non_json_returns_none() {
        assert!(extract_usage_from_json(b"not json at all").is_none());
    }

    #[test]
    fn test_extract_model_from_request_or_response() {
        let body = br#"{"model":"gpt-4o","messages":[]}"#;
        assert_eq!(extract_model_from_json(body).unwrap(), "gpt-4o");
    }

    #[test]
    fn test_anthropic_sse_message_start_carries_input_tokens() {
        let event = r#"{"type":"message_start","message":{"id":"msg_1","usage":{"input_tokens":150,"output_tokens":1}}}"#;
        let usage = extract_usage_from_sse_event(event).unwrap();
        assert_eq!(usage.input_tokens, 150);
    }

    #[test]
    fn test_anthropic_sse_message_delta_carries_output_tokens() {
        let event = r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}"#;
        let usage = extract_usage_from_sse_event(event).unwrap();
        assert_eq!(usage.output_tokens, 42);
    }

    #[test]
    fn test_anthropic_sse_content_block_delta_has_no_usage() {
        let event =
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}"#;
        assert!(extract_usage_from_sse_event(event).is_none());
    }

    #[test]
    fn test_openai_sse_final_chunk_carries_usage() {
        let event = r#"{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":30,"completion_tokens":12,"total_tokens":42}}"#;
        let usage = extract_usage_from_sse_event(event).unwrap();
        assert_eq!(usage.input_tokens, 30);
        assert_eq!(usage.output_tokens, 12);
    }

    #[test]
    fn test_usage_accumulator_merges_input_then_output_across_events() {
        let mut acc = UsageAccumulator::new();
        acc.observe_sse_event(
            r#"{"type":"message_start","message":{"usage":{"input_tokens":150,"output_tokens":0}}}"#,
        );
        acc.observe_sse_event(r#"{"type":"content_block_delta"}"#); // no usage — ignored
        acc.observe_sse_event(r#"{"type":"message_delta","usage":{"output_tokens":75}}"#);

        let usage = acc.usage();
        assert_eq!(usage.input_tokens, 150);
        assert_eq!(usage.output_tokens, 75);
    }

    #[test]
    fn test_usage_accumulator_later_output_wins_over_earlier() {
        // Cumulative output_tokens grows across message_delta events.
        let mut acc = UsageAccumulator::new();
        acc.observe_sse_event(r#"{"type":"message_delta","usage":{"output_tokens":10}}"#);
        acc.observe_sse_event(r#"{"type":"message_delta","usage":{"output_tokens":25}}"#);
        assert_eq!(acc.usage().output_tokens, 25);
    }

    #[test]
    fn test_fallback_token_estimate_from_bytes() {
        assert_eq!(estimate_tokens_from_bytes(400), 100);
        assert_eq!(estimate_tokens_from_bytes(0), 0);
        assert_eq!(estimate_tokens_from_bytes(1), 1); // never zero for nonempty input
    }

    #[test]
    fn test_estimate_cost_usd_matches_pricing_table() {
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
        };
        let cost = estimate_cost_usd("anthropic", "claude-sonnet-5", usage);
        assert!((cost - 18.0).abs() < 1e-9); // 3.0 input + 15.0 output per 1M
    }

    #[test]
    fn test_estimate_cost_usd_zero_usage_is_zero_cost() {
        let cost = estimate_cost_usd("openai", "gpt-4o", TokenUsage::default());
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn test_sse_usage_from_bytes_anthropic_stream() {
        let body = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":150,\"output_tokens\":1}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n",
        );
        let usage = sse_usage_from_bytes(body.as_bytes()).unwrap();
        assert_eq!(usage.input_tokens, 150);
        assert_eq!(usage.output_tokens, 42);
    }

    #[test]
    fn test_sse_usage_from_bytes_openai_stream_with_done_marker() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5}}\n\n",
            "data: [DONE]\n\n",
        );
        let usage = sse_usage_from_bytes(body.as_bytes()).unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
    }

    #[test]
    fn test_sse_usage_from_bytes_no_usage_returns_none() {
        let body = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        assert!(sse_usage_from_bytes(body.as_bytes()).is_none());
    }

    #[test]
    fn test_sse_usage_from_bytes_handles_truncated_final_event() {
        // Simulates the cost-tap cap cutting off mid-event — must not panic
        // and should still recover usage from earlier complete events.
        let body = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":99,\"output_tokens\":0}}}\n\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tok",
        );
        let usage = sse_usage_from_bytes(body.as_bytes()).unwrap();
        assert_eq!(usage.input_tokens, 99);
        assert_eq!(usage.output_tokens, 0);
    }
}
