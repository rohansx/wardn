# wardn

**A credential firewall for AI agents.**

The headline claim is structural, not policy: agents receive placeholder tokens,
never real API keys. The real key crosses only one network seam — inside the
wardn proxy, on its way to the upstream API — and is stripped from responses
before they reach the agent. Logs, environment, LLM context windows, scratch
files, and shell history hold only placeholders.

```text
agent process       OPENAI_KEY=wdn_placeholder_a1b2c3d4e5f6g7h8     (useless)
agent logs          Authorization: Bearer wdn_placeholder_a1b2...     (useless)
LLM context         wdn_placeholder_a1b2c3d4e5f6g7h8                   (useless)
wardn proxy         injects the real key in-flight, single seam        (deleted on response)
~/.vibeguard/vault.enc   AES-256-GCM(Argon2id(passphrase))             (encrypted at rest)
```

This is the load-bearing claim and it's defensible today against agent
compromise, prompt injection, log theft, and skill exfiltration.
Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the honest split
between what is covered and what isn't — including the tier where the
stronger "host compromise leaks nothing" claim becomes reachable.

The vault itself (encrypted at rest, passphrase-derived key) is a real
component and the reason the firewall can run on a single machine. The
upcoming [docs/HOSTED-TIER.md](docs/HOSTED-TIER.md) tier additionally
wraps the proxy in a confidential-compute enclave so even a fully
compromised VPS cannot read the key.

[![Crates.io](https://img.shields.io/crates/v/wardn.svg)](https://crates.io/crates/wardn)
[![License](https://img.shields.io/crates/l/wardn.svg)](LICENSE)

## The Problem

Every AI agent framework today stores API keys in environment variables or
`.env` files. A compromised agent, malicious skill, commodity stealer, or
prompt injection exfiltrating `Authorization: Bearer sk-...` from an LLM
log gets full access to your credentials.

```
~/.env              → OPENAI_KEY=sk-proj-real-key      # plaintext, readable by anyone
agent context       → "Use OPENAI_KEY=sk-proj-real-key" # leaked into LLM context window
agent logs          → Authorization: Bearer sk-proj-... # sitting in log files
```

## The Fix: A Credential Firewall

wardn hands agents a useless placeholder string and removes the real key
from every surface it can reach. Real keys are injected at the network
layer — a single seam — and stripped from responses before they reach
the agent.

```
agent environment   → OPENAI_KEY=wdn_placeholder_a1b2c3d4e5f6g7h8   (useless)
wardn vault         → OPENAI_KEY=sk-proj-real-key                     (encrypted at rest)
upstream request    → Authorization: Bearer sk-proj-real-key          (network transit only)
upstream response   → ...real keys stripped, placeholders returned... (re-injected on the way back)
agent logs          → Authorization: Bearer wdn_placeholder_a1b2...   (useless)
LLM context window  → wdn_placeholder_a1b2c3d4e5f6g7h8               (useless)
```

## Architecture

```mermaid
flowchart TB
    subgraph Agent["AI Agent Process"]
        A1["Agent Code"]
        A2["ENV: OPENAI_KEY=wdn_placeholder_a1b2..."]
    end

    subgraph Wardn["wardn daemon · localhost:7777"]
        direction TB
        P["HTTP Proxy"]
        MCP["MCP Server\n(stdio)"]

        subgraph Pipeline["Request Pipeline"]
            direction LR
            S1["Identify\nAgent"] --> S2["Resolve\nPlaceholder"] --> S3["Check\nAuth"] --> S4["Rate\nLimit"] --> S5["Inject\nReal Key"]
        end

        subgraph ResponsePipeline["Response Pipeline"]
            direction RL
            R1["Strip Real\nKeys"] --> R2["Replace with\nPlaceholders"]
        end

        subgraph Vault["Encrypted Vault"]
            V1["AES-256-GCM"]
            V2["Argon2id KDF"]
            V3["Placeholder Map\nper agent × credential"]
        end
    end

    subgraph External["External APIs"]
        E1["api.openai.com"]
        E2["api.anthropic.com"]
        E3["..."]
    end

    A1 -- "placeholder token\nin headers/body" --> P
    A1 -. "MCP: get_credential_ref\nlist_credentials\ncheck_rate_limit" .-> MCP
    MCP -. "placeholder token\n(never real keys)" .-> A1
    P --> Pipeline
    Pipeline --> External
    External --> ResponsePipeline
    ResponsePipeline -- "response with\nplaceholders only" --> A1
    Pipeline <--> Vault
    ResponsePipeline <--> Vault

    style Agent fill:#1a1a2e,stroke:#e94560,color:#fff
    style Wardn fill:#0f3460,stroke:#16213e,color:#fff
    style Pipeline fill:#16213e,stroke:#e94560,color:#fff
    style ResponsePipeline fill:#16213e,stroke:#e94560,color:#fff
    style Vault fill:#1a1a2e,stroke:#00d2ff,color:#fff
    style External fill:#0a0a0a,stroke:#533483,color:#fff
```

## How It Works

```
Agent sends request with placeholder in Authorization header
         │
         ▼
┌─────────────────────────┐
│      wardn proxy        │
│    localhost:7777        │
│                         │
│  1. Identify agent      │
│  2. Resolve placeholder │
│  3. Check authorization │
│  4. Check rate limit    │
│  5. Inject real key     │
│  6. Forward request     │
│  7. Strip key from resp │
│  8. Return to agent     │
└─────────────────────────┘
         │
         ▼
   External API (only place real key exists in transit)
```

## Demo

<p align="center">
  <img src="demo/wardn-demo.gif" alt="wardn demo" width="800">
</p>

## Trust Levels, Honest

| Tier | Where | What holds |
|---|---|---|
| **Self-host (today)** | your laptop, your VPS, CI | Encrypted-at-rest vault, firewall claim against agents. **Does not** defend against root on the host. |
| **Hosted (upcoming)** | wardn-managed or BYO-cloud | Confidential-compute enclave (Nitro / SEV-SNP) + remote attestation + encrypt-to-the-proxy flow. Real "host compromise leaks nothing" claim. |

The self-host tier is the load-bearing claim and ships today. The hosted tier
is the strict-upgrade path: it costs money and operational complexity, and
its design is in [docs/HOSTED-TIER.md](docs/HOSTED-TIER.md). Full honest
inventory of what is and isn't covered:

👉 **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** — covers / does-not-cover
table, "no software vault eliminates host compromise" called out plainly, and
the upgrade path.

## Install

```bash
# Prebuilt binary (Linux/macOS, amd64/arm64), checksum-verified
curl -sSf https://raw.githubusercontent.com/rohansx/wardn/main/install.sh | sh

# or from crates.io
cargo install wardn

# or Homebrew, once the tap is published (see Formula/wardn.rb)
brew install rohansx/wardn/wardn
```

## Quick Start

```bash
# Create an encrypted vault and store your keys
wardn vault create
wardn vault set OPENAI_KEY
wardn vault set ANTHROPIC_KEY

# Set up Claude Code integration (one command)
wardn setup claude-code
```

That's it. Claude Code now uses wardn's MCP server to get placeholder tokens instead of reading real keys from your environment.

### What happens next

1. Claude Code calls `get_credential_ref` → gets `wdn_placeholder_a1b2...` (not the real key)
2. Agent sends request with placeholder through wardn proxy
3. Proxy swaps placeholder for real key, forwards to API
4. Proxy strips real key from response before returning to agent

The real key never enters the agent's memory, logs, or LLM context window.

## Local Dashboard

Once the daemon is up (`wardn serve`, or spawned by `wardn run`), open
**http://127.0.0.1:7777/ui** in a browser. A read-only, local-only view of:

- **Credentials** — every stored credential with its ACLs (allowed agents,
  allowed domains, rate limit + budget badges).
- **Recent Activity** — the last 50 proxy events with method, domain,
  path, status, agent, request_id, and recorded cost (`request_completed`,
  `credential_injected`, `rate_limit`, `budget_exceeded`, `loop_detected`,
  `request_error`).
- **Budgets** — every credential's configured budget (max, spent,
  remaining, window, mode) with a progress bar that turns warn → bad as
  it crosses 50% / 80%.

Polled automatically every 2 s. No mutation endpoints — the only way
out of the dashboard is the API itself (`/api/summary`, `/api/credentials`,
`/api/audit?limit=N`, `/api/budgets`).

```bash
# Static, anonymous, never sees real keys
curl http://127.0.0.1:7777/api/summary | jq
```

### Manual setup

```bash
# Get a placeholder token (never the real key)
wardn vault get OPENAI_KEY
# → wdn_placeholder_a1b2c3d4e5f6g7h8

# List stored credentials (names only, no values)
wardn vault list

# Start the proxy
wardn serve

# Start proxy + MCP server for Claude Code / Cursor
wardn serve --mcp --agent my-agent
```

## CLI Reference

### Vault Management

```bash
wardn vault create                        # create encrypted vault
wardn vault set OPENAI_KEY                # store credential (prompts for value, no echo)
wardn vault get OPENAI_KEY                # get placeholder token (never the real value)
wardn vault get OPENAI_KEY --agent bot    # get placeholder for specific agent
wardn vault list                          # list all credentials
wardn vault rotate OPENAI_KEY             # rotate value, placeholders unchanged
wardn vault remove OPENAI_KEY             # remove credential

# Custom vault path
wardn --vault /path/to/vault.enc vault list
```

### Proxy Server

```bash
wardn serve                               # HTTP proxy on 127.0.0.1:7777
wardn serve --host 0.0.0.0 --port 8080    # custom bind address
wardn serve --config wardn.toml           # load config with rate limits + ACLs
wardn serve --mcp --agent my-agent        # proxy + MCP server (stdio)
```

### Claude Code / Cursor Integration

```bash
wardn setup claude-code                   # register wardn as MCP server in Claude Code
wardn setup cursor                        # register wardn as MCP server in Cursor

# Or manually:
claude mcp add --transport stdio --scope user wardn -- wardn serve --mcp --agent claude-code
```

#### What `wardn setup` does

1. Prompts for your vault passphrase and verifies it can open the vault
2. Finds the `wardn` binary path on your system
3. Registers wardn as an MCP server:
   - **Claude Code**: runs `claude mcp add` with `WARDN_PASSPHRASE` in the env config
   - **Cursor**: writes to `~/.cursor/mcp.json` with the passphrase in `env`
4. On next launch, the IDE spawns `wardn serve --mcp` as a subprocess

#### Verifying it works

After running setup, restart your IDE and try these prompts:

```
"List my wardn credentials"
→ Claude calls list_credentials, shows credential names (never values)

"Get me a reference to OPENAI_KEY"
→ Claude calls get_credential_ref, gets wdn_placeholder_... (not the real key)

"Check my rate limit for OPENAI_KEY"
→ Claude calls check_rate_limit, shows remaining quota
```

#### MCP tools available

| Tool | What it returns | Security |
|------|----------------|----------|
| `get_credential_ref` | Placeholder token (`wdn_placeholder_...`) | Never the real value |
| `list_credentials` | Credential names + metadata | Filtered by agent's access |
| `check_rate_limit` | Remaining quota, retry info | Read-only |

### Credential Migration

```bash
wardn migrate --dry-run                             # audit Claude Code dir for exposed keys
wardn migrate --source claude-code                  # scan + migrate to vault
wardn migrate --source open-claw                    # scan OpenClaw config
wardn migrate --source directory --path ./my-proj   # scan any directory
```

### Importing Credentials

```bash
# Classic .env file (KEY=value, comments, optional `export`, quoted values
# with backslash escapes honored)
wardn import dotenv ./.env

# JSON or YAML file. Format inferred from extension; either a flat map
# or a structured {credentials: [{name, value}, ...]} shape.
wardn import file ./creds.json
wardn import file ./creds.yaml

# 1Password CLI — reuses your signed-in `op` session. Default name is
# derived from the ref's last segment; override with --name.
wardn import one-password op://Personal/openai/api_key
wardn import one-password op://Work/anthropic/token --name ANTHROPIC_KEY

# stdin — read .env-format lines. Useful for piping.
echo 'OPENAI_KEY=sk-...' | wardn import stdin
```

Each importer prompts for the vault passphrase on first use (or reads it
from `WARDN_PASSPHRASE` / the OS keychain). Existing values are silently
overwritten — the importer is value-only, metadata (allowed agents /
domains / rate limit / budget) is preserved.

### Automation

For CI/scripts, set `WARDN_PASSPHRASE` and `WARDN_VALUE` env vars to skip interactive prompts:

```bash
WARDN_PASSPHRASE=my-pass wardn vault list
WARDN_PASSPHRASE=my-pass WARDN_VALUE=sk-proj-xxx wardn vault set OPENAI_KEY
```

## Library API

Add to your `Cargo.toml`:

```toml
[dependencies]
wardn = "0.4"
```

### Vault Operations

```rust
use wardn::{Vault, config::CredentialConfig};

// Create an encrypted vault
let vault = Vault::create("vault.enc", "my-passphrase")?;

// Store a credential
vault.set_with_config("OPENAI_KEY", "sk-proj-real-key-123", &CredentialConfig {
    allowed_agents: vec!["researcher".into(), "writer".into()],
    allowed_domains: vec!["api.openai.com".into()],
    rate_limit: Some(RateLimitConfig { max_calls: 200, per: TimePeriod::Hour }),
})?;

// Agent gets a placeholder (not the real key)
let placeholder = vault.get_placeholder("OPENAI_KEY", "researcher")?;
// → "wdn_placeholder_a1b2c3d4e5f6g7h8"

// Rotate the real key — all placeholders keep working
vault.rotate("OPENAI_KEY", "sk-proj-new-key-456")?;
```

### HTTP Proxy

```rust
use wardn::daemon::{Daemon, DaemonConfig};

let daemon = Daemon::new(vault, DaemonConfig::default());
daemon.serve_proxy().await?;
```

### MCP Server

```rust
use wardn::mcp::WardenMcpServer;

// Serve over stdio (for Claude Code, Cursor, etc.)
WardenMcpServer::serve_stdio(vault, rate_limiter, "agent-id".into()).await?;
```

MCP tools exposed (read-only, no credential values ever returned):

| Tool | Description |
|------|-------------|
| `get_credential_ref` | Get your placeholder token for a credential |
| `list_credentials` | List credentials you're authorized to access |
| `check_rate_limit` | Check your remaining quota |

## Security Properties

| Property | Guarantee |
|----------|-----------|
| No credential in agent memory | Agent process only holds placeholder strings |
| No credential on disk in plaintext | AES-256-GCM encrypted vault with Argon2id KDF |
| No credential in logs | Only placeholders appear in any log output |
| No credential in LLM context | Placeholder injected into env, real key at network layer |
| Bounded cost exposure | Token bucket rate limits per credential per agent |
| Credential echo protection | Real keys stripped from API responses before reaching agent |
| Memory safety | `SensitiveString`/`SensitiveBytes` zeroed on drop |
| Atomic persistence | Write-tmp-then-rename prevents vault corruption |

## What This Defeats

| Attack | How wardn stops it |
|--------|-------------------|
| `.env` credential theft | No `.env` files. Keys only in encrypted vault |
| Malicious skill reads `$OPENAI_KEY` | Gets `wdn_placeholder_...` — useless |
| Stealer targets agent config | Finds only placeholder tokens |
| Prompt injection exfiltrates key | Key never in agent context window |
| Agent logs contain credentials | Logs contain only placeholder strings |
| Full agent compromise | Attacker has a useless placeholder |
| Cost runaway from looping agent | Rate limit per credential per agent |

## How Is This Different From...

| Tool | What it does | How wardn differs |
|------|-------------|-------------------|
| **Secrets managers** (Vault, AWS SM, 1Password) | Secure storage + retrieval | Agent still gets the real key at runtime. Wardn ensures the agent never touches it. |
| **Varlock** | Schema-based `.env` validation + AI-safe config | Focuses on config management and leak scanning. Wardn does runtime credential injection — the key never enters the agent process. |
| **OpenRouter** | API routing + key management | Trusts the client with an API key. Wardn doesn't — agent holds a useless placeholder. |
| **dotenv + .gitignore** | Keep secrets out of git | Keys still in memory, env vars, logs. Wardn removes them from all three. |
| **Service meshes** (Istio, Linkerd) | Service-to-service auth | Solve infra-level mTLS. Wardn solves agent-to-API auth where the agent itself is untrusted. |

For a deeper comparison against wardn's closest direct peers (Infisical
Agent Vault, 1Password for Agents, LiteLLM virtual keys) and how wardn's
guarantees map to OWASP's Agentic Top 10 and the MCP spec's security
guidance, see [docs/comparison.md](docs/comparison.md).

### Trust Boundary

Wardn concentrates trust in a single local process (the proxy) instead of spreading it across every plugin, tool, and LLM context window. This is a smaller attack surface, not zero attack surface:

- The proxy runs locally as a subprocess spawned by your IDE or shell — same trust level as your kernel
- The vault is encrypted at rest and only decrypted in-memory with your passphrase
- If your local machine is fully compromised, wardn can't help (nothing can)
- The placeholder token is a bearer token to the proxy — but it only works via `localhost:7777`, not against real APIs, and can be rate-limited and revoked per-agent

## Audit Logging

Every credential access is logged with a unique request ID for traceability:

```
INFO request_id=a1b2c3 agent=claude-code method=POST domain=api.openai.com path=/v1/chat/completions proxy request received
INFO request_id=a1b2c3 agent=claude-code credential=OPENAI_KEY domain=api.openai.com credential injected
INFO request_id=a1b2c3 agent=claude-code upstream_status=200 credentials_injected=1 credentials_stripped=0 proxy request completed
```

Set `RUST_LOG=wardn=info` (or `debug`/`trace`) to control verbosity. Logs go to stderr, never stdout.

## Configuration

```toml
[warden]
vault_path = "~/.vibeguard/vault.enc"

[warden.credentials.OPENAI_KEY]
rate_limit = { max_calls = 200, per = "hour" }
allowed_agents = ["researcher", "writer"]
allowed_domains = ["api.openai.com"]

[warden.credentials.ANTHROPIC_KEY]
rate_limit = { max_calls = 100, per = "hour" }
allowed_agents = ["researcher"]
allowed_domains = ["api.anthropic.com"]
```

## Project Structure

```
wardn/
├── src/
│   ├── main.rs             # CLI entry point (clap + tokio)
│   ├── cli/
│   │   ├── mod.rs          # Clap argument definitions
│   │   ├── vault_cmd.rs    # Vault subcommand handlers
│   │   ├── serve_cmd.rs    # Serve subcommand handler
│   │   ├── run_cmd.rs      # `wardn run` — lazy-starts the daemon, wires
│   │   │                   #   agent env vars, execs the child
│   │   ├── setup_cmd.rs    # Claude Code / Cursor MCP setup (+ shell alias)
│   │   └── migrate_cmd.rs  # Migrate subcommand handler
│   ├── lib.rs              # Public API, WardenError
│   ├── config.rs           # TOML configuration parsing, [upstreams] map
│   ├── vault/
│   │   ├── mod.rs          # Vault CRUD operations
│   │   ├── encryption.rs   # AES-256-GCM + Argon2id + zeroize types
│   │   ├── storage.rs      # On-disk format (WDNV), atomic writes
│   │   ├── placeholder.rs  # Token generation, per-agent isolation
│   │   └── keyring_store.rs # OS keychain passphrase storage
│   ├── proxy/
│   │   ├── mod.rs          # HTTP proxy server (axum)
│   │   ├── route.rs        # Provider-prefix vs Host-header upstream routing
│   │   ├── inject.rs       # Credential injection into requests
│   │   ├── strip.rs        # Credential stripping (shared pair-building)
│   │   ├── stream.rs       # Streaming (SSE/chunked) credential stripper
│   │   └── rate_limit.rs   # Token bucket rate limiter
│   ├── mcp/
│   │   ├── mod.rs          # MCP server (rmcp, stdio transport)
│   │   └── tools.rs        # Tool parameter/response types
│   ├── migrate/
│   │   ├── mod.rs          # Migration orchestrator + risk scoring
│   │   └── scanners/
│   │       └── credentials.rs  # API key pattern scanner
│   └── daemon/
│       └── mod.rs          # Daemon (proxy + MCP in single process)
└── tests/
    ├── cli_tests.rs        # CLI integration tests
    ├── vault_tests.rs      # Vault integration tests
    ├── proxy_tests.rs      # Proxy tests without a real upstream
    ├── proxy_e2e_tests.rs  # Real upstream via wiremock (header/body/SSE)
    └── run_cmd_tests.rs    # Real end-to-end `wardn run`
```

## Development

```bash
# Integration tests use a fast (insecure) KDF so the suite runs in
# milliseconds instead of paying the real Argon2id cost per test —
# always pass this feature flag when running tests locally or in CI:
cargo test --features test-fast-kdf

cargo build
cargo clippy --all-targets --features test-fast-kdf
```

## Vault Encryption

```mermaid
flowchart LR
    subgraph Input
        Pass["Passphrase"]
        Salt["Random Salt\n(16 bytes)"]
        Creds["Credentials\n(JSON)"]
    end

    subgraph KDF["Key Derivation"]
        Argon["Argon2id\nm=19456 t=2 p=1"]
    end

    subgraph Encrypt["Encryption"]
        AES["AES-256-GCM"]
        Nonce["Random Nonce\n(12 bytes)"]
    end

    subgraph Output["WDNV File"]
        direction TB
        Magic["WDNV (4B)"]
        Ver["Version (2B)"]
        SaltOut["Salt (16B)"]
        Payload["Nonce ‖ Ciphertext ‖ Tag"]
    end

    Pass --> Argon
    Salt --> Argon
    Argon -- "256-bit key" --> AES
    Creds --> AES
    Nonce --> AES
    AES --> Payload

    style Input fill:#1a1a2e,stroke:#e94560,color:#fff
    style KDF fill:#16213e,stroke:#00d2ff,color:#fff
    style Encrypt fill:#16213e,stroke:#00d2ff,color:#fff
    style Output fill:#0f3460,stroke:#533483,color:#fff
```

### File Format

```
Bytes 0-3:   Magic "WDNV"
Bytes 4-5:   Version (u16 LE)
Bytes 6-21:  Argon2id salt (16 bytes)
Bytes 22+:   AES-256-GCM encrypted payload (nonce ‖ ciphertext ‖ tag)
```

## Part of VibeGuard

Wardn is the credential isolation layer of VibeGuard — a security daemon for AI agents. Other planned modules:

- **Sentinel** — prompt injection firewall
- **CloakPipe** — PII redaction middleware
- **Watcher** — audit log + dashboard

## License

MIT
