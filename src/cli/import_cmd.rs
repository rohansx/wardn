//! `wardn import` — bring credentials into the vault from external sources.
//!
//! Sources supported:
//!
//! - `dotenv <path>` — parse a classic `.env`-style file (`KEY=value`,
//!   comments, blank lines, optional `export` prefix, single/double-quoted
//!   values with backslash escapes).
//! - `file <path>`   — JSON or YAML (format inferred from extension).
//!   Accepts either a flat `{KEY: value, ...}` map or a structured
//!   `{"credentials": [{"name": "X", "value": "Y"}, ...]}` shape.
//! - `1password <ref> [--name <NAME>]` — shells out to the 1Password CLI
//!   (`op read <ref>`). Reuses the user's signed-in `op` session — does
//!   not ask for a 1Password password here.
//! - `stdin`         — read `.env`-formatted lines from stdin. Useful
//!   for piping or for `echo 'K=V' | wardn import stdin`.
//!
//! Existing credential names keep their stored value untouched — the
//! per-name `vault.set` is a silent overwrite of value (not metadata),
//! which matches the existing `wardn vault set` semantics.

use std::io::Read;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use wardn::Vault;

use super::ImportCommands;

/// One parsed credential ready to store: (name, value).
pub type ParsedCredential = (String, String);

/// Run the selected import subcommand.
pub fn run(cmd: &ImportCommands, vault_path: &Path) -> Result<()> {
    let mut parsed: Vec<ParsedCredential> = match cmd {
        ImportCommands::Dotenv { path } => parse_dotenv_path(path)?,
        ImportCommands::File { path } => parse_file(path)?,
        ImportCommands::Stdin => parse_dotenv_stdin()?,
        ImportCommands::OnePassword { ref_arg, name } => parse_onepassword(ref_arg, name.as_deref())?,
    };

    if parsed.is_empty() {
        eprintln!("wardn import: no credentials found in the input.");
        return Ok(());
    }

    let passphrase = read_passphrase(vault_path)?;
    let mut vault = Vault::open(vault_path, &passphrase)
        .context("failed to open vault — check the passphrase")?;

    let n = parsed.len();
    let mut stored = 0usize;
    for (name, value) in parsed.drain(..) {
        if name.is_empty() {
            eprintln!("wardn import: skipping entry with empty credential name");
            continue;
        }
        vault
            .set(&name, &value)
            .with_context(|| format!("failed to store '{name}'"))?;
        stored += 1;
    }

    eprintln!("wardn import: stored {stored}/{n} credential(s) in {}", vault_path.display());
    Ok(())
}

fn read_passphrase(vault_path: &Path) -> Result<String> {
    if let Ok(pass) = std::env::var("WARDN_PASSPHRASE") {
        tracing::warn!("using passphrase from WARDN_PASSPHRASE env var");
        return Ok(pass);
    }
    if let Some(pass) = wardn::vault::keyring_store::retrieve_passphrase(vault_path) {
        return Ok(pass);
    }
    rpassword::prompt_password("Passphrase: ").context("failed to read passphrase")
}

/// Parse a .env file at `path`. Returns Ok(empty Vec) if the file doesn't
/// exist — that's a discovery aid, not an error here. Callers can choose
/// to fail on empty separately if they want.
fn parse_dotenv_path(path: &Path) -> Result<Vec<ParsedCredential>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(parse_dotenv(&content))
}

/// Read .env content from stdin until EOF.
fn parse_dotenv_stdin() -> Result<Vec<ParsedCredential>> {
    let mut content = String::new();
    std::io::stdin()
        .read_to_string(&mut content)
        .context("failed to read stdin")?;
    Ok(parse_dotenv(&content))
}

/// Parse classic `.env`-format text. Format per line:
///   - blank lines and lines whose first non-whitespace char is `#` are skipped
///   - leading `export ` is stripped (bash convention)
///   - first `=` splits name from value
///   - whitespace around name and value is trimmed
///   - values wrapped in `"..."` or `'...` are unquoted with backslash-escapes
///     honored for the common cases (`\\`, `\"`, `\n`, `\r`, `\t`)
///   - inline `# comments` after a value are NOT honored — that's a sharp
///     edge .env files disagree on, and we err on the side of not silently
///     dropping characters
pub fn parse_dotenv(content: &str) -> Vec<ParsedCredential> {
    let mut out = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();

        let Some((name_raw, value_raw)) = line.split_once('=') else {
            continue;
        };
        let name = name_raw.trim().to_string();
        let mut value = value_raw.trim().to_string();

        // Unquote wrapped values.
        if value.len() >= 2 {
            let bytes = value.as_bytes();
            let first = bytes[0];
            let last = bytes[value.len() - 1];
            if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
                value = value[1..value.len() - 1].to_string();
                if first == b'"' {
                    value = unescape_double_quoted(&value);
                }
            }
        }

        if name.is_empty() {
            continue;
        }
        out.push((name, value));
    }
    out
}

fn unescape_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// JSON or YAML, picked by extension.
fn parse_file(path: &Path) -> Result<Vec<ParsedCredential>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    match ext.as_str() {
        "yaml" | "yml" => parse_yaml(&content),
        "json" => parse_json(&content),
        "" => bail!("could not infer import format: {} has no extension (use .json/.yaml/.yml)", path.display()),
        other => bail!("unsupported import format extension '.{other}' (use .json, .yaml, or .yml)"),
    }
}

/// Top-level shape accepted:
///   { "KEY": "value", ... }                         — flat map
///   { "credentials": [ {"name": "X", "value": "Y"} ] } — items array
/// Either shape's values must be strings.
fn parse_json(content: &str) -> Result<Vec<ParsedCredential>> {
    #[derive(Deserialize)]
    struct Item {
        name: String,
        value: String,
    }

    let value: serde_json::Value = serde_json::from_str(content)
        .with_context(|| "invalid JSON in import file")?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("JSON root must be an object"))?;

    // Structured shape takes precedence — if the root has a `credentials`
    // (or `items`) key whose value is an array, treat it as the structured
    // shape. Otherwise walk the object as a flat string→string map.
    for key in ["credentials", "items"] {
        if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
            let mut out = Vec::with_capacity(arr.len());
            for entry in arr {
                let parsed: Item = serde_json::from_value(entry.clone())
                    .with_context(|| format!("item in `{key}` array must have `name` and `value`"))?;
                out.push((parsed.name, parsed.value));
            }
            return Ok(out);
        }
    }

    let mut out = Vec::with_capacity(obj.len());
    for (k, v) in obj {
        let value = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Null => String::new(),
            other => other.to_string(),
        };
        out.push((k.clone(), value));
    }
    Ok(out)
}

fn parse_yaml(content: &str) -> Result<Vec<ParsedCredential>> {
    // YAML is a superset of JSON for our purposes — try JSON first, then
    // fall through to serde_yaml for full YAML (anchors, lists, etc.).
    match parse_json(content) {
        Ok(v) => Ok(v),
        Err(_) => {
            #[derive(Deserialize)]
            struct Item {
                name: String,
                value: String,
            }

            let value: serde_yaml::Value = serde_yaml::from_str(content)
                .with_context(|| "invalid YAML in import file")?;
            let map = value
                .as_mapping()
                .ok_or_else(|| anyhow!("YAML root must be a mapping"))?;

            for key in ["credentials", "items"] {
                if let Some(arr) = map.get(serde_yaml::Value::String(key.to_string())) {
                    if let Some(items) = arr.as_sequence() {
                        let mut out = Vec::with_capacity(items.len());
                        for entry in items {
                            let parsed: Item = serde_yaml::from_value(entry.clone())
                                .with_context(|| {
                                    format!("item in `{key}` sequence must have `name` and `value`")
                                })?;
                            out.push((parsed.name, parsed.value));
                        }
                        return Ok(out);
                    }
                }
            }

            let mut out = Vec::with_capacity(map.len());
            for (k, v) in map {
                let key = match k {
                    serde_yaml::Value::String(s) => s.clone(),
                    other => serde_yaml::to_string(&other).unwrap_or_default().trim().to_string(),
                };
                let value = match v {
                    serde_yaml::Value::String(s) => s.clone(),
                    serde_yaml::Value::Number(n) => n.to_string(),
                    serde_yaml::Value::Bool(b) => b.to_string(),
                    serde_yaml::Value::Null => String::new(),
                    serde_yaml::Value::Mapping(_) | serde_yaml::Value::Sequence(_) => {
                        bail!("nested YAML mappings/sequences can't be imported as flat values")
                    }
                    other => serde_yaml::to_string(&other).unwrap_or_default().trim().to_string(),
                };
                out.push((key, value));
            }
            Ok(out)
        }
    }
}

/// One credential off `op read <ref>`. The name is taken from `--name`,
/// or derived from the ref's last path segment uppercased.
fn parse_onepassword(ref_arg: &str, name: Option<&str>) -> Result<Vec<ParsedCredential>> {
    if ref_arg.is_empty() {
        bail!("1password: ref cannot be empty");
    }
    let op_status = Command::new("op").arg("--version").output();
    if let Err(e) = &op_status {
        bail!(
            "1Password CLI ('op') not found in PATH — install it from https://1password.com/downloads/command-line/ ({e})"
        );
    }

    let output = Command::new("op")
        .args(["read", ref_arg])
        .output()
        .with_context(|| format!("failed to invoke 'op read {ref_arg}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "'op read {ref_arg}' failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    let value = String::from_utf8(output.stdout)
        .with_context(|| format!("op read produced non-UTF8 output for {ref_arg}"))?
        .trim_end_matches(&['\n', '\r'][..])
        .to_string();

    let name = match name {
        Some(n) => n.to_string(),
        None => derive_name_from_ref(ref_arg),
    };

    Ok(vec![(name, value)])
}

/// Best-effort name derivation from an `op://vault/item/field` style ref —
/// the last non-empty path segment, uppercased, with non-alphanumeric
/// characters turned into underscores. Falls back to "IMPORTED".
fn derive_name_from_ref(reference: &str) -> String {
    reference
        .trim_end_matches('/')
        .rsplit('/')
        .find(|s| !s.is_empty())
        .map(|segment| {
            segment
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
                .collect::<String>()
        })
        .filter(|s: &String| !s.is_empty())
        .unwrap_or_else(|| "IMPORTED".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dotenv_basic() {
        let s = "OPENAI_KEY=sk-123\nANTHROPIC_KEY=sk-ant-456\n";
        let v = parse_dotenv(s);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], ("OPENAI_KEY".to_string(), "sk-123".to_string()));
        assert_eq!(v[1], ("ANTHROPIC_KEY".to_string(), "sk-ant-456".to_string()));
    }

    #[test]
    fn test_parse_dotenv_comments_and_blanks() {
        let s = "# top comment\n\nFOO=bar\n   # indented comment\nBAZ=qux\n";
        let v = parse_dotenv(s);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, "FOO");
        assert_eq!(v[1].0, "BAZ");
    }

    #[test]
    fn test_parse_dotenv_export_prefix() {
        let s = "export OPENAI_KEY=sk-123\nexport ANOTHER=ok\n";
        let v = parse_dotenv(s);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, "OPENAI_KEY");
        assert_eq!(v[1].0, "ANOTHER");
    }

    #[test]
    fn test_parse_dotenv_double_quoted_with_escapes() {
        // Build the fixture programmatically rather than fight raw-string
        // delimiter collisions with the trailing `\"`. The intended dotenv
        // line is: KEY="line1\nline2\t\"qoted\""
        let mut s = String::from("KEY=\"");
        s.push_str(r#"line1\nline2\t\"qoted\""#);
        s.push('"');
        let v = parse_dotenv(&s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "KEY");
        assert_eq!(v[0].1, "line1\nline2\t\"qoted\"");
    }

    #[test]
    fn test_parse_dotenv_single_quoted_is_literal() {
        // Single quotes don't honor backslash escapes in classic .env.
        let s = r#"KEY='a\nb'"#;
        let v = parse_dotenv(s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "a\\nb");
    }

    #[test]
    fn test_parse_dotenv_skips_invalid_lines() {
        let s = "no-equals-sign\n=orphan-value\nGOOD=ok\n";
        let v = parse_dotenv(s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "GOOD");
    }

    #[test]
    fn test_parse_dotenv_whitespace_trimmed() {
        let s = "  KEY  =  value  \n";
        let v = parse_dotenv(s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], ("KEY".to_string(), "value".to_string()));
    }

    #[test]
    fn test_parse_json_flat_map() {
        let s = r#"{"OPENAI_KEY":"sk-1","ANTHROPIC_KEY":"sk-ant-2"}"#;
        let v = parse_json(s).unwrap();
        assert_eq!(v.len(), 2);
        let map: std::collections::HashMap<_, _> = v.into_iter().collect();
        assert_eq!(map["OPENAI_KEY"], "sk-1");
        assert_eq!(map["ANTHROPIC_KEY"], "sk-ant-2");
    }

    #[test]
    fn test_parse_json_structured() {
        let s = r#"{"credentials":[{"name":"OPENAI_KEY","value":"sk-1"}]}"#;
        let v = parse_json(s).unwrap();
        assert_eq!(v, vec![("OPENAI_KEY".to_string(), "sk-1".to_string())]);
    }

    #[test]
    fn test_parse_yaml_flat() {
        let s = "OPENAI_KEY: sk-1\nANTHROPIC_KEY: 'sk-ant-2'\n";
        let v = parse_yaml(s).unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn test_parse_yaml_structured() {
        let s = "credentials:\n  - name: OPENAI_KEY\n    value: sk-1\n";
        let v = parse_yaml(s).unwrap();
        assert_eq!(v, vec![("OPENAI_KEY".to_string(), "sk-1".to_string())]);
    }

    #[test]
    fn test_parse_file_routes_by_extension() {
        // JSON
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("creds.json");
        std::fs::write(&p, r#"{"FOO":"bar"}"#).unwrap();
        let v = parse_file(&p).unwrap();
        assert_eq!(v, vec![("FOO".to_string(), "bar".to_string())]);

        // YAML
        let py = dir.path().join("creds.yaml");
        std::fs::write(&py, "FOO: bar\n").unwrap();
        let v = parse_file(&py).unwrap();
        assert_eq!(v, vec![("FOO".to_string(), "bar".to_string())]);
    }

    #[test]
    fn test_parse_file_rejects_unknown_extension() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("creds.txt");
        std::fs::write(&p, "FOO=bar").unwrap();
        let err = parse_file(&p).unwrap_err().to_string();
        assert!(err.contains("unsupported"));
    }

    #[test]
    fn test_derive_name_from_ref() {
        assert_eq!(derive_name_from_ref("op://Personal/openai/api_key"), "API_KEY");
        assert_eq!(derive_name_from_ref("op://Work/anthropic/token"), "TOKEN");
        assert_eq!(derive_name_from_ref("op://Vault/item"), "ITEM");
    }

    #[test]
    fn test_dotenv_path_missing_file_is_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("does-not-exist.env");
        let err = parse_dotenv_path(&p).unwrap_err();
        assert!(err.to_string().contains("failed to read"));
    }
}
