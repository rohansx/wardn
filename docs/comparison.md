# wardn vs. the field

This compares wardn against the closest tools in the "credential isolation
for AI agents" category, and maps wardn's guarantees to the security
guidance that's emerged around agentic systems in 2025–2026 (OWASP's
Agentic Top 10, the MCP spec's auth guidance, and how Anthropic itself
secures Claude Code's own credentials).

Written after wardn's revival (all three arcs — see
[revival-plan.md](./revival-plan.md)): the proxy now actually routes agent
traffic (base-URL redirect, not just MCP registration), streams SSE
responses, keeps the passphrase out of agent configs, and adds dollar
budgets, loop detection, agent-bound placeholders, OAuth refresh, and
derived-secret scrubbing on top of the original vault + proxy design.

## Comparison table

| | **wardn** | **Infisical Agent Vault** | **1Password for Agents** | **LiteLLM virtual keys** |
|---|---|---|---|---|
| Core mechanism | Local encrypted vault + reverse proxy; agent holds only a placeholder token | Local vault + MITM proxy; agent holds a dummy token | SDK fetches the *real* secret at runtime via a service-account token | Gateway issues a virtual key; LLM provider key never leaves the gateway |
| Does the agent process ever hold the real secret? | **No** — placeholder only, real key injected at the network layer | No — same placeholder model | **Yes** — the SDK call returns the real secret into the agent's memory | No, for *LLM* provider keys specifically |
| Scope | Any API credential (LLM providers + arbitrary third-party APIs via `[upstreams]`) | Any API credential | Any secret 1Password manages | LLM provider keys only |
| Integration | `wardn run -- <cmd>` (base-URL env vars) or MCP registration + shell alias | Per-agent env var configuration (no one-command setup) | SDK call in your agent's code | Gateway URL + virtual key in your agent's client config |
| Spend control | Dollar-denominated per-agent budgets, hard/soft mode, `--max-cost`, loop/runaway detection | Not part of the core proxy | Not applicable (not a proxy) | Per-key budgets (paywalled at the Enterprise tier, ~$250/mo) |
| Domain scoping | Per-credential allow-list, default-prompted (not silently open) | Not enforced at the proxy | N/A | Model/route restrictions per key |
| Agent identity | Placeholder is bound to the agent it was issued to — a stolen token replayed under a different claimed identity is rejected | Identity is an unauthenticated header claim, not checked against the token | Real 1Password service-account auth | API-key based |
| Streaming (SSE) | Full incremental streaming with credential stripping | Not documented | N/A (agent has the real key, nothing to strip) | Streams through as a normal gateway |
| OAuth-backed credentials | Refresh-before-use for `refresh_token`-grant credentials | Not documented | Native (1Password manages OAuth natively) | N/A |
| Passphrase/secret storage | OS keychain (Keychain Services / Credential Manager / Secret Service), never in agent config files | Not documented | 1Password's own vault (SaaS or self-hosted) | N/A |
| Distribution | Single Rust binary, no cloud account | Go binary + Infisical account gravity for the managed tier | Managed SaaS (or self-hosted) | Self-hosted gateway (Python) or managed |
| License | MIT | MIT + proprietary `ee/` | Commercial | MIT (core) |

**Where wardn differs from every vault-centric competitor (1Password, Doppler,
HashiCorp Vault's SDK path):** those hand the real secret to the agent
process at runtime — the SDK call itself returns it. wardn's guarantee is
structural, not procedural: the agent's own environment and memory only
ever contain a `wdn_placeholder_...` string. A leaked `.env`, a committed
`mcp.json`, or a compromised agent process yields nothing usable.

**Where wardn differs from Infisical Agent Vault** (the closest architectural
peer): wardn adds dollar-budget spend control, binds placeholders to the
issuing agent (closing the "steal a token, claim to be someone else" gap),
does real SSE streaming instead of buffering, and ships a one-command
`wardn run` / `wardn setup <agent> --alias` integration path instead of
manual per-agent env var configuration.

## Mapping to OWASP's Agentic Top 10 (ASI03: Agent Identity & Privilege Abuse)

OWASP's 2026 Agentic Top 10 prescribes, for ASI03: unique per-agent identity,
short-lived task-scoped credentials, and per-step authorization. wardn's
design maps directly:

| ASI03 guidance | wardn mechanism |
|---|---|
| Unique per-agent identity | Placeholders are per-(credential, agent) pairs; `Vault::resolve_placeholder_for_agent` rejects a placeholder presented under a different claimed agent than the one it was issued to |
| Short-lived, task-scoped credentials | OAuth-backed credentials are refreshed automatically before expiry (`proxy::oauth`); dollar/call budgets cap how much any single agent identity can spend before being cut off |
| Per-step authorization | Every proxied request re-checks domain allow-list, rate limit, and budget before the real key is ever injected — not just at credential-issuance time |
| Least privilege | `allowed_domains` scopes a credential to specific hosts; empty (unrestricted) is a prompted choice for `vault set`, not a silent default |
| Audit trail | Every credential injection/strip/scrub/budget event is logged with a per-request correlation ID (`RUST_LOG=wardn=info`) |

## Mapping to the MCP spec's security guidance

The [MCP spec's security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
explicitly forbid token passthrough (an MCP server handing a caller's own
credential back to them) and warn about the confused-deputy problem. wardn's
MCP server (`get_credential_ref`, `list_credentials`, `check_rate_limit`) only
ever returns placeholder tokens and metadata — never a value that could be
replayed directly against a third-party API outside the wardn proxy.

## Mapping to Anthropic's own approach

Claude Code's own sandboxed execution mode keeps git credentials **outside**
the sandbox, translating a scoped placeholder to the real GitHub token via a
proxy the sandboxed process never sees directly — "sensitive credentials are
never inside the sandbox." wardn generalizes exactly this pattern from git
credentials specifically to *any* API credential, for any agent, running
directly on the developer's machine rather than inside a managed sandbox.

## What wardn does not claim to solve

- **Prompt-injection abuse of a legitimately-injected credential.** If an
  agent is tricked into making a request wardn is configured to authorize
  (right domain, right agent, within budget), wardn injects the real key as
  designed — the leak is of *data*, not the credential. This is a
  complementary problem to sandboxing/permission systems, not one wardn
  solves.
- **A fully compromised local machine.** wardn concentrates trust in one
  local process instead of spreading it across every tool and context
  window — a smaller attack surface, not zero attack surface. If an attacker
  has arbitrary code execution on the host, they can reach the running proxy
  the same way any local process can.
