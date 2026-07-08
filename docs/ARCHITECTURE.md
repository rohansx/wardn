# Wardn — Architecture

## Overview

Wardn is the credential isolation proxy for VibeGuard. Agents never see real API keys — they get useless placeholder tokens. Real credentials are injected at the network layer by the proxy.

## Core Flow

```
Agent env:   OPENAI_KEY=wdn_placeholder_a1b2c3d4e5f6g7h8  (useless)
Wardn vault: OPENAI_KEY=sk-proj-actual-key                 (AES-256-GCM encrypted)

Agent → api.openai.com:
  1. Request hits Wardn proxy (localhost:7777)
  2. Resolve placeholder → credential name + agent identity
  3. Authorization check (agent allowed? domain allowed?)
  4. Rate limit check (token bucket per credential per agent)
  5. Decrypt real key in memory (never on disk in plaintext)
  6. Inject real key into Authorization header
  7. Forward to api.openai.com
  8. Strip credential echoes from response
  9. Agent receives clean response with only placeholder strings
```

## Module Structure

```
wardn/
├── src/
│   ├── lib.rs              # Public API, WardenError, re-exports
│   ├── config.rs           # TOML config parsing, [upstreams] map
│   ├── cli/
│   │   ├── mod.rs          # Clap argument definitions
│   │   ├── run_cmd.rs      # `wardn run` — lazy-starts the daemon, wires
│   │   │                   #   agent env vars, execs the child
│   │   ├── serve_cmd.rs    # `wardn serve`
│   │   ├── setup_cmd.rs    # `wardn setup claude-code|cursor`
│   │   ├── vault_cmd.rs    # `wardn vault ...`
│   │   └── migrate_cmd.rs  # `wardn migrate`
│   ├── vault/
│   │   ├── mod.rs          # Vault struct, CRUD operations
│   │   ├── encryption.rs   # AES-256-GCM, Argon2id, SensitiveString/Bytes
│   │   ├── storage.rs      # On-disk format, atomic save/load
│   │   ├── placeholder.rs  # Token generation, bidirectional maps
│   │   └── keyring_store.rs # OS keychain passphrase storage (bounded-timeout)
│   ├── proxy/
│   │   ├── mod.rs          # HTTP proxy server (axum)
│   │   ├── route.rs        # Provider-prefix vs Host-header upstream routing
│   │   ├── inject.rs       # Credential injection into requests
│   │   ├── strip.rs        # Credential stripping (shared pair-building)
│   │   ├── stream.rs       # Streaming (SSE/chunked) credential stripper
│   │   └── rate_limit.rs   # Token bucket rate limiter
│   ├── mcp/
│   │   ├── mod.rs          # MCP server
│   │   └── tools.rs        # MCP tool definitions
│   ├── migrate/
│   │   ├── mod.rs
│   │   └── scanners/credentials.rs
│   └── daemon/
│       └── mod.rs          # Proxy + MCP composed into one process
└── tests/
    ├── cli_tests.rs        # CLI integration tests (vault/migrate/serve)
    ├── vault_tests.rs      # Vault lifecycle integration tests
    ├── proxy_tests.rs      # Proxy tests without a real upstream
    ├── proxy_e2e_tests.rs  # Real upstream via wiremock: header/body/SSE
    │                       #   injection and stripping, routing
    └── run_cmd_tests.rs    # Real end-to-end `wardn run`: daemon lazy-start
                             #   + child env var wiring
```

## Encryption

- **Algorithm:** AES-256-GCM (authenticated encryption)
- **Key derivation:** Argon2id from user passphrase (m=19456, t=2, p=1)
- **Memory safety:** SensitiveString/SensitiveBytes with Zeroize on drop
- **Persistence:** Atomic file writes (write .tmp → rename)
- **File format:** `WDNV` magic | version u16 | salt 16B | encrypted payload

## Placeholder Tokens

Format: `wdn_placeholder_{random_hex_16}`

- Unique per (credential, agent) pair
- Rotatable — rotating real key doesn't change placeholders
- Auditable — maps back to which agent used which credential

## Security Properties

1. No credential in agent memory
2. No credential on disk in plaintext
3. No credential in logs
4. No credential in LLM context window
5. Bounded cost via rate limits
6. Full audit trail via Watcher integration
