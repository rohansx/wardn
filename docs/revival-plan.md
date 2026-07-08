# Wardn — Revival Plan (v0.5 → v1.0)

> Status as of 2026-07-07. Supersedes the "Phase 5 Improvements" section of
> [PLAN.md](./PLAN.md). Written after a full code audit + competitive/demand
> research pass. Read the **Reality Check** first — it explains why the current
> `main` does not yet deliver its headline promise.

---

## Positioning: equal billing

Wardn makes three guarantees, presented co-equally from the homepage down:

> **Worthless if stolen. Capped if abused. Logged always.**
>
> - **Worthless if stolen** — the agent only ever holds a `wdn_placeholder_…`
>   token. A leaked `.env`, a committed config, a stealer scraping
>   `~/.claude.json` — all get useless strings.
> - **Capped if abused** — every call is metered against a per-agent, per-key
>   **dollar/token budget** with a hard stop. A looping agent can't run up a
>   $300 overnight bill.
> - **Logged always** — every credential use is attributed and audit-logged
>   with a request ID.

The two headline properties map to the two strongest signals in the research:
credential isolation is the **differentiator** (endorsed verbatim by OWASP
ASI03, the MCP spec's no-token-passthrough rule, and Anthropic's own
sandbox-proxy design for git creds); spend control is the **acquisition wedge**
(weekly, viral, first-person pain — claude-code#57719 "$313 overnight, closed
as not planned"). Neither is a bolt-on; they share the same proxy hot path.

---

## Reality Check — why the current build doesn't deliver yet

Four load-bearing facts from the audit. Each is a P0 blocker.

1. **Agent traffic never reaches the proxy.** `wardn setup claude-code`
   (`src/cli/setup_cmd.rs`) registers only the MCP server. Nothing sets a base
   URL or proxy env var, so Claude Code keeps calling `api.anthropic.com`
   directly. The proxy — where key injection happens — is never exercised.
2. **HTTPS can't be routed anyway.** The proxy selects its upstream from the
   `Host` header (`src/proxy/mod.rs:77-84`) and has no `CONNECT`/TLS support.
   A base-URL override (`OPENAI_BASE_URL=http://localhost:7777`) sends
   `Host: localhost:7777`, so the proxy forwards to itself and loops.
3. **The passphrase is stored in plaintext next to the agent.** `setup` writes
   `WARDN_PASSPHRASE` into `~/.cursor/mcp.json` / the Claude MCP config
   (`setup_cmd.rs:64-79,134-148`) — the exact file class stealers enumerate.
   Anyone who reads it decrypts the whole vault. Threat-model collapse.
4. **A placeholder is an exfiltration primitive by default.** CLI-created creds
   have empty `allowed_domains` = allow-all (`src/vault/mod.rs:251-258`), and
   there's no CLI to scope them. A process with a placeholder can point `Host:`
   at an attacker and have wardn inject the real key into that request.

Supporting gaps: SSE streaming is buffered whole (`src/proxy/mod.rs:207`) so
chat integrations break; agent identity is a spoofable `x-warden-agent` header
never checked against the token (`src/proxy/inject.rs:13-17`,
`src/vault/mod.rs:226-230`); a novel agent name bypasses rate limits entirely
(`src/proxy/rate_limit.rs:94-100`); `migrate` stores a marker not the real
value (`src/migrate/mod.rs:158-169`); config ACLs never reach enforcement; and
there is **no end-to-end proxy test** (the declared `wiremock` dev-dep is
unused).

The code itself is clean — near-zero unwraps, no `todo!`s, solid audit logging.
The gaps are architectural, not hygiene. This plan closes them in three arcs.

---

## Arc P0 — Make the core loop work and stop self-sabotage

Goal: a first-run user can go from `cargo install wardn` to a Claude Code
session whose API calls provably pass through wardn with the real key injected
and stripped — and the passphrase is never written to disk in plaintext.

Ship as **v0.5.0**. This arc alone is the difference between a demo and a tool.

| Step | File(s) | What |
|------|---------|------|
| P0.1 | `src/cli/run_cmd.rs` (new), `src/cli/mod.rs` | **`wardn run -- <agent> [args]`.** Lazy-start the daemon if not up, resolve placeholders for the agent's creds, set `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL`/etc. to the local proxy and the auth token to the placeholder, then `exec` the child. This is the validated integration path and sidesteps TLS MITM entirely. The single most important feature in the plan. |
| P0.2 | `src/proxy/mod.rs`, `src/proxy/route.rs` (new) | **Base-URL routing, not Host routing.** Accept `/{provider}/<path>` prefixes or a configured `upstream_map` (provider → real base URL) so a base-URL override reaches the right API instead of looping. Keep Host routing as a fallback for explicit forward-proxy users. |
| P0.3 | `src/proxy/stream.rs` (new), `src/proxy/mod.rs`, `src/proxy/strip.rs` | **SSE / chunked passthrough.** Detect `text/event-stream` (and chunked bodies) and stream chunks through with incremental placeholder-strip on a sliding buffer, instead of `.bytes().await` buffering the whole response. Non-negotiable for chat agents. |
| P0.4 | `src/vault/keyring.rs` (new), `src/cli/setup_cmd.rs`, `Cargo.toml` | **Passphrase out of config.** Store/retrieve the passphrase via OS keychain (`keyring` crate → Secret Service / macOS Keychain / WinCred), or a socket-activated unlock daemon. `setup` stops writing `WARDN_PASSPHRASE` into any agent config. One unlock per login session. |
| P0.5 | `src/cli/setup_cmd.rs` | **`setup` wires the proxy too.** Emit the `wardn run` wrapper (or base-URL env for the agent's launch config) alongside the MCP registration, so the proxy path is actually used, not just MCP. |
| P0.6 | `tests/proxy_e2e_tests.rs` (new) | **Real end-to-end test** using the already-declared `wiremock` dep: placeholder in request → mock upstream receives real key → response with the key is stripped back to a placeholder. Cover header + JSON body + one SSE stream. |
| P0.7 | `src/proxy/inject.rs` | **Robust placeholder matching.** Replace the fixed-width 32-char slice (`inject.rs:24-32`) with a proper token scan (regex/anchored parse) that handles end-of-buffer and adjacent hex. |

**P0 exit criteria:** `wardn run -- claude` produces a working session; audit log
shows `credential injected` / `credentials_stripped`; an SSE completion streams
token-by-token; no plaintext passphrase on disk; `cargo test` includes a green
inject→forward→strip e2e.

---

## Arc P1 — The spend-control wedge

Goal: dollar-denominated, per-agent, per-key budgets with a hard stop and a live
meter — the thing claude-code#57719 begged for and no provider offers per-key.
Ship as **v0.6.0**.

| Step | File(s) | What |
|------|---------|------|
| P1.1 | `src/proxy/cost/mod.rs` (new), `src/proxy/cost/pricing.rs` (new) | **Cost estimator.** Per-provider/model pricing table; estimate request cost from token counts (parse usage from response bodies where available, else estimate from request). Keep pricing in a data file that's easy to update. |
| P1.2 | `src/vault/budget.rs` (new), `src/config.rs`, `src/vault/mod.rs` | **Budget model.** Per-agent × per-credential budgets denominated in USD or tokens, with window (day/week/month/total) and hard vs. soft mode. Extend `CredentialConfig` and TOML schema. |
| P1.3 | `src/proxy/mod.rs`, `src/proxy/budget_gate.rs` (new) | **Hard-stop gate.** Before injecting, check remaining budget; on exhaustion return a clear 402/429 with a wardn error body and log it. Deduct actual cost post-response. |
| P1.4 | `src/cli/budget_cmd.rs` (new), `src/cli/mod.rs` | **CLI + `--max-cost`.** `wardn budget set <cred> --agent <a> --usd 5/day`; `wardn run --max-cost 2.00 -- <agent>`; `wardn budget status` (live spend readout). |
| P1.5 | `src/proxy/loop_guard.rs` (new) | **Runaway detection.** Detect tight retry/identical-request loops (rolling window on request hash + rate) and trip an early hard stop before the budget is even hit. |
| P1.6 | `src/cli/serve_cmd.rs` (or a TUI line) | **Live spend meter** printed to the terminal / queryable, so the user sees `$0.42 / $5.00 today` while the agent runs. |
| P1.7 | `src/cli/vault_cmd.rs`, `src/vault/mod.rs` | **Fix default scope (security + spend).** Add `--domain` to `vault set`; default new creds to a **deny-all** domain posture with a clear prompt, closing the exfiltration-primitive hole from Reality Check #4. |

**P1 exit criteria:** an agent stuck in a loop is stopped at its dollar cap;
`wardn budget status` shows accurate spend; a placeholder can only reach its
allowlisted host.

---

## Arc P2 — Harden the security claims + differentiators + launch

Goal: make "per-agent revocation" and "identity" real, cover more agents, and
ship loud. Ship as **v0.7 → v1.0**.

| Step | File(s) | What |
|------|---------|------|
| P2.1 | `src/proxy/auth.rs` (new), `src/vault/placeholder.rs`, `src/proxy/mod.rs` | **Bind placeholder ↔ caller.** Give each agent a per-session proxy secret (issued at `wardn run` launch, not a spoofable header); verify it on every request and check the token's agent binding. Makes per-agent revocation and rate-limit attribution actually enforceable (fixes Reality Check identity gaps). |
| P2.2 | `src/proxy/oauth.rs` (new) | **OAuth token refresh/exchange** for creds that are OAuth-backed — the #1 gap the Infisical Agent Vault HN thread flagged, and the bridge toward the Auth0/Arcade world. |
| P2.3 | `src/proxy/strip.rs` | **Derived-token scrubbing.** Beyond exact-key match, mask secrets *returned* in bodies (e.g. a login endpoint emitting a session token) — Lasso-style, opt-in per credential. |
| P2.4 | `src/cli/setup_cmd.rs`, `src/cli/setup/*` | **More agents.** Extend `setup` to Codex, Gemini CLI, OpenCode, Aider. Each reuses the P0.5 wiring. |
| P2.5 | `src/migrate/mod.rs` | **Finish migrate.** Actually move discovered secrets into the vault (currently a stub marker), with a confirm step. |
| P2.6 | `docs/comparison.md` (new), `README.md` | **Comparison table + OWASP mapping.** "wardn vs Agent Vault vs 1Password vs LiteLLM"; map guarantees to OWASP ASI03 and the MCP no-passthrough rule for the security-review copy-paste answer. Wardn already leads on response-strip + rate limits + one-command setup — say so. |
| P2.7 | `install.sh`, Homebrew tap, MCP Registry, curl-installer | **Distribution.** crates.io reaches Rust devs only. Add `brew install`, a `curl \| sh` installer, publish to the MCP Registry and Docker MCP Catalog. |
| P2.8 | `docs/benchmarks.md` (new) | **Publish TTFT overhead numbers.** The Rust opening vs LiteLLM's P99 blowups — quantify the added latency of the proxy hop and streaming strip. |

**P2 exit criteria:** a stolen placeholder is rejected at the proxy (bound to
caller); `setup` covers ≥4 agents; a comparison page + benchmarks exist; wardn
is installable via brew/curl and listed in the MCP Registry.

---

## Non-goals (explicit)

- **No default TLS MITM.** Cert-trust hell across Node/Bun/Python + SSE
  breakage; base-URL redirect (P0.1/P0.2) is the validated path. A MITM mode
  can stay an opt-in advanced feature, never the default.
- **No enterprise agentic-IAM play.** Keycard ($38M), Arcade ($72M), 1Password,
  Okta, AWS, Microsoft already own that. Wardn's lane is the local-first,
  single-binary, no-cloud-account developer running coding agents — the niche
  where Varlock got 3.7k stars with zero funding. A team tier (shared vault
  sync, central audit) is a *later* consideration, not this plan.
- **Not an agent-behavior control.** Wardn is a credential-at-rest + spend
  control. It does not stop prompt-injection abuse of a legitimately-injected
  key over an allowlisted host (Bucket B incidents). Compose with
  sandbox-runtime/devcontainers; don't over-claim.

---

## Distribution note (as important as any feature)

The repo being dormant Mar 26 → Jul 7 *is* the message. Infisical's Agent Vault
launched two days after wardn, kept shipping weekly, ran a Show HN (156 pts),
and now has ~1,800 stars to wardn's 35 — it won on visible cadence, not a better
idea. A "Show HN: wardn" has never happened, and this exact pitch reliably
scores 150+ points. **Sequence: finish P0, then launch loud** (Show HN +
r/rust + comparison SEO), then P1 as the follow-up that keeps people. The Agent
Vault HN thread's criticisms (OAuth refresh, response-body reflection, selective
injection, runtime approval) are a free P1/P2 checklist — ship them and launch
against them.

---

## Suggested version map

| Version | Contains | Headline |
|---------|----------|----------|
| v0.5.0 | Arc P0 | "It actually works now: real key injected at the proxy, passphrase in keychain." |
| v0.6.0 | Arc P1 | "Denial of wallet: hard dollar budgets + `--max-cost` for any agent." |
| v0.7.0 | P2.1–P2.3 | "Real per-agent identity + OAuth refresh." |
| v1.0.0 | P2.4–P2.8 | "Every major coding agent, one command; brew/curl/MCP-Registry; benchmarked." |
