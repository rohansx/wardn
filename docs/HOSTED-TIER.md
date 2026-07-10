# wardn hosted tier — design

**Status: design document, not shipped code.** The self-host tier
([README](../README.md), [THREAT-MODEL](THREAT-MODEL.md)) is what runs today.
This doc is the architecture the self-host tier's honest limits point at — the
upgrade path, written down before it's built so the claims stay checkable.

Read [THREAT-MODEL.md](THREAT-MODEL.md) first. This doc only covers what the
hosted tier *adds*.

---

## The one gap it closes

Every software vault — wardn's self-host tier included — has the same
irreducible limit: **the real key is plaintext in host memory for the
milliseconds it's injected into a request.** Root on the host can read
`/proc/<pid>/mem`, attach a debugger, or scrape a core dump and get the key.
The self-host tier makes that *detectable* (tamper-evident audit) but not
*preventable*.

The hosted tier's single job is to move those milliseconds of plaintext
somewhere the host operator — including a fully compromised host — cannot
reach. Nothing else here matters if that doesn't hold.

## Architecture

Three pieces, none of them novel — the contribution is wiring them to the
existing proxy without changing its request semantics.

```
                     ┌─────────────────────────────────────────┐
   client / agent    │  host (untrusted)                        │
   ┌──────────┐      │   ┌───────────────────────────────────┐  │
   │ placeholder ───────►│  wardn proxy (unchanged)          │  │
   │  wdn_...  │◄────────┤  sees only ciphertext + placeholders │
   └──────────┘      │   │                                   │  │
        │ attest     │   │   ┌───────────────────────────┐   │  │
        └────────────────────►│  ENCLAVE (Nitro/SEV-SNP)  │   │  │
          challenge   │   │   │  • holds vault decrypt key │   │  │
          + pubkey    │   │   │  • inject/strip happens    │   │  │
                      │   │   │    HERE, in attested code  │   │  │
                      │   │   └───────────────────────────┘   │  │
                      │   └───────────────────────────────────┘  │
                      └─────────────────────────────────────────┘
   real key is plaintext ONLY inside the enclave, ONLY during a request
```

1. **Confidential compute.** The credential-bearing part of the proxy —
   inject and strip — runs inside an AWS Nitro Enclave or an AMD SEV-SNP VM.
   Outside the enclave (including in the host's own kernel) the real key
   exists only as ciphertext. Inside, only for the request window.

2. **Remote attestation.** A client challenges the enclave and gets back a
   signed *measurement* (proof of which code is running) plus a per-session
   public key bound to that measurement. The client verifies the measurement
   against a known-good value before trusting anything.

3. **Encrypt-to-the-proxy.** The secret is encrypted *to the attested
   enclave's session public key*. Ciphertext crosses the internet and the
   host; only the attested enclave holds the matching private key. A full
   host compromise never sees plaintext because plaintext never enters host
   memory.

## Request lifecycle (attested)

```
1. client → enclave:  attestation challenge (nonce)
2. enclave → client:  measurement + session pubkey, signed by the platform
3. client verifies measurement == expected  (else abort — you're not talking
                                              to the code you think you are)
4. client → proxy:    request carrying wdn_placeholder_… as before
5. proxy → enclave:   placeholder + upstream target
6. enclave:           decrypt real key, enforce policy, inject, forward,
                      strip the key from the response
7. enclave → proxy → client:  response with placeholder restored
```

Steps 4–7 are byte-for-byte the self-host flow. The only new surface is the
attestation handshake and the enclave boundary — the agent-facing contract
(placeholder in, placeholder out) is identical, so nothing downstream changes.

## What changes vs self-host

| Threat | Self-host today | Hosted tier |
|---|---|---|
| **Root on the host** | Detect via audit ledger; key is readable in `/proc` mem | Key never in host memory as plaintext — root sees ciphertext only |
| **Compromise during a request window** | Bug in inject/strip can leak for some traffic shape | Bounded to the enclave; blast radius = what policy allowed in the window, then revoked |
| **"Is this the real binary?"** | Trust cargo + crates.io | Attested measurement — cryptographic proof of the running code |

It does **not** change the operator-config gap: an `allowed_domains = []`
credential is still a foot-gun, in any tier. Policy is enforced *inside* the
enclave, but you still have to write a sane policy.

## What you trust instead

The hosted tier doesn't abolish trust — it *relocates* it, to things that are
externally verifiable:

- **The platform vendor's enclave firmware** (AWS Nitro, or AMD for SEV-SNP)
  instead of your whole host OS. Smaller, audited, attestable surface.
- **A reproducible build** whose measurement you (or a third party) can
  reproduce from source — closing the "is this the binary I think it is?"
  gap that the self-host tier leaves to cargo/crates.io honesty.
- **The operator still rotates after a detected compromise.** The ledger
  helps you notice; nothing forces the rotation. Unchanged from self-host.

If trusting a cloud vendor's enclave is itself unacceptable, the honest
upstream answer remains an HSM and its operational cost — see
[THREAT-MODEL.md](THREAT-MODEL.md#what-youre-trusting).

## Implementation roadmap

Ordered by dependency; each phase is independently useful.

1. **Reproducible builds + signed releases.** Prerequisite for a meaningful
   measurement. Deliverable before any enclave work — it also hardens the
   self-host tier's "trust the binary" gap on its own.
2. **Enclave harness.** Split inject/strip into an enclave-hostable component
   with a minimal host↔enclave RPC. Vault decrypt key lives only inside.
3. **Attestation endpoint.** `POST /attestation/challenge` → measurement +
   session pubkey; client-side verification library.
4. **Encrypt-to-proxy client flow.** SDK/base-URL shim encrypts the secret to
   the attested pubkey instead of sending it in the clear to a local proxy.
5. **Policy in attested code.** Move per-credential policy
   (`time_windows`, `allowed_models`, `request_shape`) enforcement inside the
   enclave so the compromise-window blast radius is what an *attacker* can do,
   not what the host operator can rewrite.

Phases 1 and 5's policy surface are also self-host-tier improvements — they
land there first, then get pulled behind the enclave boundary.

## Honest status

This is a roadmap, not a shipped feature. Do not deploy anything on the
assumption the hosted tier exists yet. When it ships, this doc becomes the
operator guide and its claims become testable against attestation output. The
short version, unchanged from [THREAT-MODEL.md](THREAT-MODEL.md#a-short-version):

```
wardn hosted tier = self-host code + Nitro/SEV-SNP enclave + remote attestation
                  + encrypt-to-the-proxy + policy in attested code
                  (host compromise leaks only what policy allowed in the window)
```
