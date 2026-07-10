# Threat Model

The framing of wardn today is **a credential firewall for AI agents**. That
is the strongest claim that ships, and it's the line that the README leads
with. This page is the honest inventory of what's covered, what isn't, and
what changes between the tiers.

If you came here looking for "this solves credential theft on the server,"
read [the hosted-tier design doc](HOSTED-TIER.md) — that is a roadmap, not
a shipped feature. If you came here looking for marketing copy, this isn't
it.

## Two tiers

```text
                    ┌─────────────────────────┐                  ┌────────────────────────┐
   self-host        │  your box / your VPS    │   upgrade path  │  enclave-backed tier   │
   (today, free)    │  plain Rust process     │ ──────────────▶ │  (Nitro / SEV-SNP,     │
                    │  encrypted-at-rest vault│                  │   attestation,         │
                    │                         │                  │   encrypt-to flow)     │
                    └─────────────────────────┘                  └────────────────────────┘
                              │                                           │
                              ▼                                           ▼
                    defendable claims:                          defendable claims:
                    • agent never sees real key                 • everything in self-host
                    • vault at rest is AES-256-GCM             • host compromise leaks
                    • rate limit, budget, ACLs                    only "what policy allowed"
                    • tamper-evident audit ledger                 inside the compromise
                                                                 window
                    honest gaps:
                    • host root = full leak                     honest gaps:
                    • single passphrase is a SPOF               • a bug/backdoor in the
                                                                 enclave binary breaks all
                    risks it WILL NOT eliminate:                 of it
                    • misuse within policy during                • keys can still be used
                      compromise window                          within policy during the
                                                                 window
                    mitigations on the roadmap:                  mitigations on the roadmap:
                    • Shamir split (k-of-n) of the               • reproducible builds so
                      master passphrase                         attestation actually means
                                                                 something
```

Both tiers are explicit about the limits. The threat model is the same in
shape — only the depth changes.

## Self-host tier — what's covered

These guarantees hold against the threat classes the wardn proxy is
designed to address. The proxy runs as a normal Unix process; under the
trust assumption that the host OS is not actively malicious, every item
below is structural, not policy.

| Concern | What holds | How |
|---|---|---|
| `.env` file exfiltration | Nothing lives there. | Keys only ever sit in `~/.vibeguard/vault.enc`. |
| Agent reads `$OPENAI_KEY` | It reads a placeholder. | Env vars are minted with the placeholder at `wardn run` time. |
| Malicious skill reads `$OPENAI_KEY` | Same as agent — placeholder. | The skill has the same process boundary as the agent. |
| Stealer exfiltrating shell env | Same — placeholder only. | Real key never enters the shell environment. |
| Log collection captures `Authorization: Bearer sk-...` | Stays placeholder. | Response stream scrubs keys before reaching caller. |
| Prompt injection that exfiltrates the key from the LLM | The key isn't there to exfiltrate. | LLM context holds placeholders, not real values. |
| Full agent compromise (backdoored skill, hijacked MCP transport) | Attacker has a useless placeholder. | Attacker can do only what policy + rate limit / budget allow. |
| Stuck-agent retry loop burning cost | Detected and stopped. | Per-credential-per-agent token bucket + loop fingerprint guard. |
| Vault file at rest | AES-256-GCM (96-bit nonce) over a 256-bit key derived from passphrase via Argon2id (m=19456 KiB, t=2, p=1). | Atomic write-tmp-then-rename. Writes are `fsync`'d. |
| Audit log tampering (in-process buffer) | Detected. | Append-only hash-chained ledger on disk (BLAKE3 chain). See `wardn.toml`. |

## Self-host tier — what is **not** covered

These are the limits we cannot honestly defend against in this tier.

| Concern | Why we can't claim it | Mitigation in this tier |
|---|---|---|
| **Root on the host** | Real keys are decoded into the proxy process. Root can read `/proc/<pid>/mem`, attach a debugger, or wait for a core dump. | Tamper-evident audit ledger so a leak can be *detected* even if not *prevented*. (Documented limit; the hosted tier is the upgrade path.) |
| **Single passphrase is a SPOF** | Forgetting it locks you out. Disclosure of it unlocks everything. | `wardn split` / `wardn unseal` Shamir-split the master into k-of-n shards printed as offline copies. |
| **Compromise during a request window** | A bug in inject/strip can leak keys for some traffic shape. | Hash-chained audit + per-credential policy; rotated promptly if hit. The hosted tier further reduces this to a defined blast radius inside an enclave. |
| **Untrusted-upstream exfiltration** | If `allowed_domains` is empty, the placeholder can be pointed at *any* host via the proxy — which would inject the real key into a request to an attacker. | `wardn vault set` refuses empty domains without a confirmation prompt; the dashboard add-credential form warns and recommends explicit domains. |
| **A bug or backdoor in wardn itself** | Code review is not a cryptographic guarantee. | Reproducible builds in CI; signed releases (roadmap). The audit ledger surfaces anomalies even if not prevents them. |
| **Replay of leaked placeholders** | A leaked placeholder for agent X, presented to the proxy with `x-warden-agent: Y`, would resolve Y's policy (or be denied under spoofed claim). | Placeholders are per-credential-per-agent; the injector verifies the agent claim against the placeholder's issued agent. |

No single tool covers all of these. We're honest about which subset each
tier addresses.

## Hosted tier — what's different

The hosted tier is the same Rust code plus three things the self-host tier
doesn't have:

1. **Confidential compute.** The proxy runs inside a Nitro Enclave (or
   SEV-SNP VM). Real keys exist only as ciphertext outside the enclave and
   only as plaintext inside it, for the milliseconds of a request.
2. **Remote attestation.** A client may challenge the enclave for a
   measurement and a per-session public key. The secret is encrypted
   *to that public key* — ciphertext travels over the internet. Only the
   attested enclave decrypts it. A full VPS compromise cannot read the
   secret, because it never crosses into host memory in plaintext.
3. **Held outside the host's policy.** Even if the proxy is fully hijacked,
   the only thing the attacker can do is whatever the policy allows inside
   the compromise window. After revocation, the blast radius is bounded.

Full design and what the implementation roadmap looks like is in
[docs/HOSTED-TIER.md](HOSTED-TIER.md). That doc is currently a design
description — code follows.

## What we promise to be honest about

- **No software vault eliminates host compromise.** We will not pretend
  otherwise. The hosted tier narrows this to a defined blast radius; it
  does not abolish it. Vaults that claim otherwise are less credible than
  the ones that say "we reduce blast radius to a defined policy."
- **"All your keys were exposed" detection, not prevention.** Tamper-
  evident logs tell you *something happened*. They don't tell you ahead
  of time. The leak window is what it is.
- **Configuration is on the operator.** A vault with `allowed_domains = []`
  *will* let a placeholder be pointed at an attacker's host. We refuse
  this in interactive mode; if you're scripting with `WARDN_VALUE` set,
  you opted into the louder warning. We document this loudly; we don't
  pretend we've eliminated the class of bug.

## What you're trusting

When you start `wardn serve`:

1. You're trusting this binary. The hosted tier's reproducible builds make
   that verifiable cryptographically. The self-host tier currently
   relies on cargo + crates.io being honest.
2. You're trusting the OS process to not expose its memory to an attacker.
   Enclaves reduce this trust to a third party (AWS Nitro's code).
3. You're trusting the operator (you) to actually rotate keys after a
   compromise. The audit ledger helps you notice; nothing forces you.

If any of those trusts is uncomfortable, the upstream answer is "the
hosted tier." If the hosted tier is uncomfortable, the upstream answer
is "use a hardware security module and accept the operational cost."
We stop there.

## A short version

```
wardn today       = credential firewall + encrypted vault + tamper-evident audit
                   (host compromise leaks the keys, every tier of every tool does)

wardn soon        = + Cedar-shape policy (time, model, request-shape)
                   + Shamir split for the master passphrase

wardn hosted tier = + Nitro/SEV-SNP enclave + remote attestation
                   + encrypt-to-the-proxy + Cedar policy in attested code
                   (host compromise leaks only what policy allowed in the window)
```

Read the [hosted-tier design](HOSTED-TIER.md) if you want the architecture.
