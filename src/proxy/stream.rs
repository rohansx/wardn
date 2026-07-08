use std::collections::BTreeSet;

use super::strip::ReplacementPairs;

/// Fixed hold-back for regex scrub patterns, in addition to whatever the
/// exact-value pairs require. Regex matches have no statically-known
/// length the way a literal secret value does, so this is a documented,
/// generous bound rather than a computed exact one: a scrub pattern match
/// spanning more than this many bytes across a chunk boundary can be
/// missed. Real-world secret-shaped patterns (session tokens, API keys)
/// are well within this.
const SCRUB_HOLD_BACK: usize = 512;

/// Strips credential values from a response body as it streams through,
/// without buffering the whole response.
///
/// SSE (`text/event-stream`) and other chunked responses arrive as a
/// sequence of arbitrarily-sized byte chunks — a secret value can be split
/// across a chunk boundary. This holds back up to `longest_secret_len - 1`
/// trailing bytes of each processed chunk (the `carry`) and prepends it to
/// the next chunk before scanning again, so a split match is still caught.
/// `flush()` must be called once the upstream stream ends to emit the final
/// carried bytes.
pub struct StreamingStripper {
    pairs: Vec<(Vec<u8>, Vec<u8>, String)>,
    max_pair_len: usize,
    /// Regex-based scrub patterns: (pattern, owning credential name). A
    /// match is replaced with `[REDACTED]` — a one-way scrub, not a
    /// placeholder swap, since these are secrets wardn never issued and
    /// has nothing to hand back for.
    scrub_regexes: Vec<(regex::bytes::Regex, String)>,
    carry: Vec<u8>,
    stripped: BTreeSet<String>,
    scrubbed: BTreeSet<String>,
}

impl StreamingStripper {
    pub fn new(pairs: ReplacementPairs) -> Self {
        let byte_pairs: Vec<(Vec<u8>, Vec<u8>, String)> = pairs
            .into_iter()
            .map(|(real, placeholder, name)| (real.into_bytes(), placeholder.into_bytes(), name))
            .collect();
        let max_pair_len = byte_pairs
            .iter()
            .map(|(real, ..)| real.len())
            .max()
            .unwrap_or(0);

        Self {
            pairs: byte_pairs,
            max_pair_len,
            scrub_regexes: Vec::new(),
            carry: Vec::new(),
            stripped: BTreeSet::new(),
            scrubbed: BTreeSet::new(),
        }
    }

    /// Attach regex scrub patterns (builder-style) — see `scrub_regexes`.
    pub fn with_scrub_patterns(
        mut self,
        scrub_regexes: Vec<(regex::bytes::Regex, String)>,
    ) -> Self {
        self.scrub_regexes = scrub_regexes;
        self
    }

    /// True if there's nothing to strip or scrub — callers can skip the
    /// stripper entirely and pass chunks straight through.
    pub fn is_noop(&self) -> bool {
        self.pairs.is_empty() && self.scrub_regexes.is_empty()
    }

    /// Credential names actually stripped so far (across all chunks).
    pub fn stripped_credentials(&self) -> Vec<String> {
        self.stripped.iter().cloned().collect()
    }

    pub fn stripped_count(&self) -> usize {
        self.stripped.len()
    }

    /// Credential names whose scrub pattern matched and redacted something.
    pub fn scrubbed_credentials(&self) -> Vec<String> {
        self.scrubbed.iter().cloned().collect()
    }

    pub fn scrubbed_count(&self) -> usize {
        self.scrubbed.len()
    }

    /// Process one chunk from the upstream stream, returning the bytes safe
    /// to emit now. Some trailing bytes may be held back internally.
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.is_noop() {
            return chunk.to_vec();
        }

        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let replaced = replace_all(&buf, &self.pairs, &mut self.stripped);
        let scrubbed = scrub_all(&replaced, &self.scrub_regexes, &mut self.scrubbed);

        let hold_back = self
            .max_pair_len
            .saturating_sub(1)
            .max(if self.scrub_regexes.is_empty() {
                0
            } else {
                SCRUB_HOLD_BACK
            });
        if scrubbed.len() > hold_back {
            let split_at = scrubbed.len() - hold_back;
            self.carry = scrubbed[split_at..].to_vec();
            scrubbed[..split_at].to_vec()
        } else {
            self.carry = scrubbed;
            Vec::new()
        }
    }

    /// Emit any bytes held back after the upstream stream has ended.
    pub fn flush(&mut self) -> Vec<u8> {
        let buf = std::mem::take(&mut self.carry);
        if self.is_noop() || buf.is_empty() {
            return buf;
        }
        let replaced = replace_all(&buf, &self.pairs, &mut self.stripped);
        scrub_all(&replaced, &self.scrub_regexes, &mut self.scrubbed)
    }
}

fn replace_all(
    haystack: &[u8],
    pairs: &[(Vec<u8>, Vec<u8>, String)],
    stripped: &mut BTreeSet<String>,
) -> Vec<u8> {
    let mut buf = haystack.to_vec();
    for (needle, replacement, name) in pairs {
        if needle.is_empty() {
            continue;
        }
        let (replaced, matched) = replace_bytes(&buf, needle, replacement);
        buf = replaced;
        if matched {
            stripped.insert(name.clone());
        }
    }
    buf
}

fn scrub_all(
    haystack: &[u8],
    scrub_regexes: &[(regex::bytes::Regex, String)],
    scrubbed: &mut BTreeSet<String>,
) -> Vec<u8> {
    if scrub_regexes.is_empty() {
        return haystack.to_vec();
    }
    let mut buf = haystack.to_vec();
    for (re, name) in scrub_regexes {
        if re.is_match(&buf) {
            buf = re.replace_all(&buf, b"[REDACTED]".as_slice()).into_owned();
            scrubbed.insert(name.clone());
        }
    }
    buf
}

fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(haystack.len());
    let mut matched = false;
    let mut i = 0;
    while i < haystack.len() {
        if haystack.len() - i >= needle.len() && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            matched = true;
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    (out, matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs() -> ReplacementPairs {
        vec![(
            "sk-proj-real-key-123".to_string(),
            "wdn_placeholder_aaaaaaaaaaaaaaaa".to_string(),
            "OPENAI_KEY".to_string(),
        )]
    }

    fn session_scrub() -> Vec<(regex::bytes::Regex, String)> {
        vec![(
            regex::bytes::Regex::new(r"sess_[a-zA-Z0-9]{10,}").unwrap(),
            "OPENAI_KEY".to_string(),
        )]
    }

    #[test]
    fn test_scrub_redacts_derived_secret_within_single_chunk() {
        let mut s = StreamingStripper::new(vec![]).with_scrub_patterns(session_scrub());
        let mut out = s.process_chunk(b"data: {\"session\": \"sess_ab12cd34ef56\"}\n\n");
        out.extend(s.flush());

        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("sess_ab12cd34ef56"));
        assert!(text.contains("[REDACTED]"));
        assert_eq!(s.scrubbed_credentials(), vec!["OPENAI_KEY".to_string()]);
    }

    #[test]
    fn test_scrub_redacts_secret_split_across_chunk_boundary() {
        let mut s = StreamingStripper::new(vec![]).with_scrub_patterns(session_scrub());
        let secret = "sess_ab12cd34ef56gh78";
        let (first, second) = secret.split_at(10);

        let mut out = s.process_chunk(format!("token={first}").as_bytes());
        out.extend(s.process_chunk(format!("{second} end").as_bytes()));
        out.extend(s.flush());

        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains(secret),
            "secret leaked across boundary: {text}"
        );
        assert!(text.contains("[REDACTED]"));
    }

    #[test]
    fn test_scrub_and_strip_both_apply_together() {
        // A response containing BOTH the injected credential's real value
        // (exact-match strip) AND an unrelated derived secret (regex
        // scrub) must have both handled.
        let mut s = StreamingStripper::new(pairs()).with_scrub_patterns(session_scrub());
        let mut out =
            s.process_chunk(b"leaked key: sk-proj-real-key-123, session: sess_ab12cd34ef56");
        out.extend(s.flush());

        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("sk-proj-real-key-123"));
        assert!(text.contains("wdn_placeholder_aaaaaaaaaaaaaaaa"));
        assert!(!text.contains("sess_ab12cd34ef56"));
        assert!(text.contains("[REDACTED]"));
        assert_eq!(s.stripped_count(), 1);
        assert_eq!(s.scrubbed_count(), 1);
    }

    #[test]
    fn test_scrub_no_match_leaves_text_untouched() {
        let mut s = StreamingStripper::new(vec![]).with_scrub_patterns(session_scrub());
        let mut out = s.process_chunk(b"nothing secret in here");
        out.extend(s.flush());
        assert_eq!(out, b"nothing secret in here");
        assert!(s.scrubbed_credentials().is_empty());
    }

    #[test]
    fn test_is_noop_false_when_only_scrub_patterns_present() {
        let s = StreamingStripper::new(vec![]).with_scrub_patterns(session_scrub());
        assert!(!s.is_noop());
    }

    #[test]
    fn test_noop_when_no_pairs() {
        let mut s = StreamingStripper::new(vec![]);
        assert!(s.is_noop());
        assert_eq!(s.process_chunk(b"hello world"), b"hello world");
        assert_eq!(s.flush(), b"");
    }

    #[test]
    fn test_strips_secret_within_single_chunk() {
        let mut s = StreamingStripper::new(pairs());
        let mut out = s.process_chunk(b"data: {\"key\": \"sk-proj-real-key-123\"}\n\n");
        out.extend(s.flush());

        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("sk-proj-real-key-123"));
        assert!(text.contains("wdn_placeholder_aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn test_strips_secret_split_across_chunk_boundary() {
        let mut s = StreamingStripper::new(pairs());
        let secret = "sk-proj-real-key-123";
        let (first_half, second_half) = secret.split_at(10);

        let mut out = s.process_chunk(format!("prefix {first_half}").as_bytes());
        out.extend(s.process_chunk(format!("{second_half} suffix").as_bytes()));
        out.extend(s.flush());

        let text = String::from_utf8(out).unwrap();
        assert!(
            !text.contains(secret),
            "secret leaked across chunk boundary: {text}"
        );
        assert!(text.contains("wdn_placeholder_aaaaaaaaaaaaaaaa"));
        assert!(text.starts_with("prefix "));
        assert!(text.ends_with(" suffix"));
    }

    #[test]
    fn test_strips_secret_split_byte_by_byte() {
        // Worst case: every chunk is a single byte.
        let mut s = StreamingStripper::new(pairs());
        let secret = "sk-proj-real-key-123";
        let mut out = Vec::new();
        for b in secret.bytes() {
            out.extend(s.process_chunk(&[b]));
        }
        out.extend(s.flush());

        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains(secret));
        assert!(text.contains("wdn_placeholder_aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn test_no_match_passes_through_unchanged() {
        let mut s = StreamingStripper::new(pairs());
        let mut out = s.process_chunk(b"just some normal streamed text, nothing secret here");
        out.extend(s.flush());
        assert_eq!(out, b"just some normal streamed text, nothing secret here");
    }

    #[test]
    fn test_tracks_stripped_credentials_within_chunk() {
        let mut s = StreamingStripper::new(pairs());
        s.process_chunk(b"leak: sk-proj-real-key-123");
        s.flush();
        assert_eq!(s.stripped_credentials(), vec!["OPENAI_KEY".to_string()]);
        assert_eq!(s.stripped_count(), 1);
    }

    #[test]
    fn test_tracks_stripped_credentials_split_across_chunks() {
        let mut s = StreamingStripper::new(pairs());
        s.process_chunk(b"sk-proj-real-");
        s.process_chunk(b"key-123");
        s.flush();
        assert_eq!(s.stripped_credentials(), vec!["OPENAI_KEY".to_string()]);
    }

    #[test]
    fn test_no_stripped_credentials_when_nothing_matches() {
        let mut s = StreamingStripper::new(pairs());
        s.process_chunk(b"nothing secret here");
        s.flush();
        assert!(s.stripped_credentials().is_empty());
        assert_eq!(s.stripped_count(), 0);
    }

    #[test]
    fn test_multiple_sse_events_across_many_chunks() {
        let mut s = StreamingStripper::new(pairs());
        let chunks: Vec<&[u8]> = vec![
            b"event: token\ndata: hel",
            b"lo\n\nevent: token\ndata: sk-proj-real-key",
            b"-123 leaked\n\n",
        ];

        let mut out = Vec::new();
        for c in chunks {
            out.extend(s.process_chunk(c));
        }
        out.extend(s.flush());

        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("sk-proj-real-key-123"));
        assert!(text.contains("hello"));
        assert!(text.contains("wdn_placeholder_aaaaaaaaaaaaaaaa"));
    }
}
