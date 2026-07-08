use wardn::config::{CredentialConfig, RateLimitConfig, TimePeriod};
use wardn::{Vault, WardenError};

use tempfile::TempDir;

#[test]
fn test_full_vault_lifecycle() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.enc");

    // Create vault and store credentials
    {
        let mut vault = Vault::create_fast(&path, "secure-passphrase").unwrap();

        vault
            .set_with_config(
                "OPENAI_KEY",
                "sk-proj-real-key-123",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["researcher".to_string(), "writer".to_string()],
                    allowed_domains: vec!["api.openai.com".to_string()],
                    rate_limit: Some(RateLimitConfig {
                        max_calls: 200,
                        per: TimePeriod::Hour,
                    }),
                },
            )
            .unwrap();

        vault
            .set_with_config(
                "ANTHROPIC_KEY",
                "sk-ant-real-key-456",
                &CredentialConfig {
                    scrub_patterns: Vec::new(),
                    oauth: None,
                    budget: None,
                    allowed_agents: vec!["researcher".to_string()],
                    allowed_domains: vec!["api.anthropic.com".to_string()],
                    rate_limit: None,
                },
            )
            .unwrap();

        vault.set("TELEGRAM_TOKEN", "bot123:ABC-token").unwrap();

        assert_eq!(vault.len(), 3);
    }

    // Reopen and verify state persisted
    {
        let mut vault = Vault::open_fast(&path, "secure-passphrase").unwrap();
        assert_eq!(vault.len(), 3);
        assert_eq!(
            vault.get("OPENAI_KEY").unwrap().expose(),
            "sk-proj-real-key-123"
        );

        // Get placeholders for different agents
        let ph_researcher = vault.get_placeholder("OPENAI_KEY", "researcher").unwrap();
        let ph_writer = vault.get_placeholder("OPENAI_KEY", "writer").unwrap();
        assert_ne!(ph_researcher, ph_writer);

        // Unauthorized agent gets error
        let err = vault.get_placeholder("OPENAI_KEY", "hacker").unwrap_err();
        assert!(matches!(err, WardenError::Unauthorized { .. }));

        // Resolve placeholder to real value
        let resolved = vault.resolve_placeholder(ph_researcher.as_str()).unwrap();
        assert_eq!(resolved.0, "OPENAI_KEY");
        assert_eq!(resolved.1.expose(), "sk-proj-real-key-123");

        // Rotate credential — placeholder unchanged, value updated
        vault.rotate("OPENAI_KEY", "sk-proj-new-key-789").unwrap();
        let ph_after = vault.get_placeholder("OPENAI_KEY", "researcher").unwrap();
        assert_eq!(ph_researcher, ph_after);

        let resolved = vault.resolve_placeholder(ph_researcher.as_str()).unwrap();
        assert_eq!(resolved.1.expose(), "sk-proj-new-key-789");

        // Remove credential
        vault.remove("TELEGRAM_TOKEN").unwrap();
        assert_eq!(vault.len(), 2);
        assert!(vault.get("TELEGRAM_TOKEN").is_none());
    }

    // Wrong passphrase fails
    {
        let result = Vault::open_fast(&path, "wrong-passphrase");
        assert!(matches!(result, Err(WardenError::DecryptionFailed)));
    }
}

#[test]
fn test_list_never_exposes_values() {
    let mut vault = Vault::ephemeral();
    vault.set("SECRET_KEY", "super-secret-value").unwrap();

    let list = vault.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "SECRET_KEY");
    // CredentialInfo has no value field — compile-time guarantee
}

#[test]
fn test_domain_authorization() {
    let mut vault = Vault::ephemeral();
    vault
        .set_with_config(
            "KEY",
            "secret",
            &CredentialConfig {
                scrub_patterns: Vec::new(),
                oauth: None,
                budget: None,
                allowed_agents: vec![],
                allowed_domains: vec!["api.openai.com".to_string()],
                rate_limit: None,
            },
        )
        .unwrap();

    assert!(vault.is_domain_allowed("KEY", "api.openai.com"));
    assert!(!vault.is_domain_allowed("KEY", "evil.com"));
    assert!(!vault.is_domain_allowed("MISSING", "api.openai.com"));
}

#[test]
fn test_open_access_when_no_allowed_agents() {
    let mut vault = Vault::ephemeral();
    vault.set("KEY", "value").unwrap(); // no allowed_agents

    // Any agent should be able to get a placeholder
    assert!(vault.get_placeholder("KEY", "anyone").is_ok());
    assert!(vault.is_agent_authorized("KEY", "anyone"));
}

#[test]
fn test_open_access_when_no_allowed_domains() {
    let mut vault = Vault::ephemeral();
    vault.set("KEY", "value").unwrap(); // no allowed_domains

    // Any domain should be allowed
    assert!(vault.is_domain_allowed("KEY", "anything.com"));
}

#[test]
fn test_debug_does_not_leak_secrets() {
    let mut vault = Vault::ephemeral();
    vault.set("KEY", "super-secret-api-key").unwrap();

    let value = vault.get("KEY").unwrap();
    let debug_output = format!("{value:?}");
    assert_eq!(debug_output, "[REDACTED]");
    assert!(!debug_output.contains("super-secret"));
}

#[test]
fn test_placeholders_persist_across_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.enc");

    let placeholder;
    {
        let mut vault = Vault::create_fast(&path, "pass").unwrap();
        vault.set("KEY", "secret").unwrap();
        placeholder = vault.get_placeholder("KEY", "agent-1").unwrap();
    }

    // Reopen and verify placeholder still resolves
    let vault = Vault::open_fast(&path, "pass").unwrap();
    let resolved = vault.resolve_placeholder(placeholder.as_str()).unwrap();
    assert_eq!(resolved.0, "KEY");
    assert_eq!(resolved.1.expose(), "secret");
}

#[test]
fn test_multiple_credentials_persist() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.enc");

    {
        let mut vault = Vault::create_fast(&path, "pass").unwrap();
        for i in 0..10 {
            vault
                .set(&format!("KEY_{i}"), &format!("value_{i}"))
                .unwrap();
        }
    }

    let vault = Vault::open_fast(&path, "pass").unwrap();
    assert_eq!(vault.len(), 10);
    for i in 0..10 {
        assert_eq!(
            vault.get(&format!("KEY_{i}")).unwrap().expose(),
            format!("value_{i}")
        );
    }
}
