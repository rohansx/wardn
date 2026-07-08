use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use keyring::Entry;

use crate::WardenError;

const SERVICE: &str = "wardn";
const OP_TIMEOUT: Duration = Duration::from_secs(3);

fn account_for(vault_path: &Path) -> String {
    vault_path
        .canonicalize()
        .unwrap_or_else(|_| vault_path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

/// Run a blocking keyring operation on a background thread with a bounded
/// timeout.
///
/// Some platform backends — notably Secret Service over D-Bus — can hang
/// indefinitely instead of failing when there's no session bus available:
/// a headless server, a container, or a sandboxed agent runtime. wardn must
/// never hang the caller because of that; a timeout is treated the same as
/// "keychain unavailable" so the caller can fall back (env var / prompt).
fn with_timeout<T: Send + 'static>(
    op: impl FnOnce() -> crate::Result<T> + Send + 'static,
) -> crate::Result<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(op());
    });

    rx.recv_timeout(OP_TIMEOUT).unwrap_or_else(|_| {
        Err(WardenError::Keyring(
            "OS keychain did not respond in time (no keychain/Secret Service session available?)"
                .to_string(),
        ))
    })
}

/// Store a vault passphrase in the OS keychain (Keychain Services on macOS,
/// Windows Credential Manager, or Secret Service on Linux), keyed by the
/// vault's canonical path so multiple vaults don't collide.
///
/// Unlike `wardn setup`'s old behavior, this is the only place a passphrase
/// should be persisted — never write it into an agent's own config file
/// (e.g. an MCP server's env block), since any process that can read that
/// file can then decrypt the whole vault.
pub fn store_passphrase(vault_path: &Path, passphrase: &str) -> crate::Result<()> {
    let account = account_for(vault_path);
    let passphrase = passphrase.to_string();
    with_timeout(move || {
        let entry =
            Entry::new(SERVICE, &account).map_err(|e| WardenError::Keyring(e.to_string()))?;
        entry
            .set_password(&passphrase)
            .map_err(|e| WardenError::Keyring(e.to_string()))
    })
}

/// Retrieve a previously stored passphrase.
///
/// Returns `None` if nothing is stored, the backend is unavailable, or the
/// lookup times out — all three are "no passphrase from the keychain" as
/// far as callers are concerned, and every caller here has a further
/// fallback (env var, interactive prompt).
pub fn retrieve_passphrase(vault_path: &Path) -> Option<String> {
    let account = account_for(vault_path);
    let result = with_timeout(move || {
        let entry =
            Entry::new(SERVICE, &account).map_err(|e| WardenError::Keyring(e.to_string()))?;
        match entry.get_password() {
            Ok(pass) => Ok(Some(pass)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(WardenError::Keyring(e.to_string())),
        }
    });

    match result {
        Ok(pass) => pass,
        Err(e) => {
            tracing::debug!(error = %e, "OS keychain unavailable, falling back");
            None
        }
    }
}

/// Remove a stored passphrase. A no-op if none was stored or the backend is
/// unavailable — deletion failing silently is acceptable here since the
/// worst case is a stale keychain entry, not a security hole.
pub fn delete_passphrase(vault_path: &Path) {
    let account = account_for(vault_path);
    let result = with_timeout(move || {
        let entry =
            Entry::new(SERVICE, &account).map_err(|e| WardenError::Keyring(e.to_string()))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(WardenError::Keyring(e.to_string())),
        }
    });

    if let Err(e) = result {
        tracing::debug!(error = %e, "failed to delete OS keychain entry");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_account_for_uses_absolute_path_string() {
        let account = account_for(Path::new("/tmp/does-not-exist/vault.enc"));
        assert!(account.ends_with("vault.enc"));
        assert!(account.starts_with('/'));
    }

    #[test]
    fn test_retrieve_never_hangs_when_backend_unavailable() {
        // This sandbox has no D-Bus session/Secret Service daemon, so this
        // exercises the real "keychain unavailable" path — retrieval must
        // still return within OP_TIMEOUT rather than hanging the caller.
        let start = Instant::now();
        let result = retrieve_passphrase(Path::new("/tmp/wardn-keyring-test-nonexistent"));
        let elapsed = start.elapsed();

        assert!(result.is_none());
        assert!(
            elapsed < OP_TIMEOUT + Duration::from_secs(2),
            "retrieve_passphrase took {elapsed:?}, expected it to bail out near the {OP_TIMEOUT:?} timeout"
        );
    }

    #[test]
    fn test_delete_never_hangs_when_backend_unavailable() {
        let start = Instant::now();
        delete_passphrase(Path::new("/tmp/wardn-keyring-test-nonexistent"));
        let elapsed = start.elapsed();

        assert!(
            elapsed < OP_TIMEOUT + Duration::from_secs(2),
            "delete_passphrase took {elapsed:?}, expected it to bail out near the {OP_TIMEOUT:?} timeout"
        );
    }
}
