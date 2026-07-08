# Proxy-hop overhead

The single biggest objection to any local proxy sitting in front of an LLM
API is latency — nobody wants to add hundreds of milliseconds to every
agent turn. This measures what wardn actually adds: vault lookup, agent
identity check, domain/rate-limit/budget checks, and credential injection.

## Methodology

A local mock upstream (Python `http.server`, no TLS, no real network hop)
was used so the measurement isolates *wardn's own* overhead from internet/API
latency, which is identical whether or not wardn is in the path and would
otherwise dominate and hide the number we actually care about. Two response
shapes were tested:

- **Plain JSON** (`POST /v1/messages` → a small non-streaming JSON body)
- **SSE streaming** (`POST /v1/messages/stream` → 5 `data: ...` chunks with
  a 10ms gap between them, approximating real token-by-token streaming)

For each shape, 30 requests were sent directly to the mock upstream, and 30
through `wardn serve` (release build, `--config` pointing a custom
`[warden.upstreams]` slug at the mock server, a real vault-stored credential,
real placeholder-token injection — the full P0–P2 code path, not a stub).
`curl -w '%{time_starttransfer} %{time_total}'` measured, per request,
time-to-first-byte (TTFB — the proxy equivalent of TTFT for a streaming
response) and total request time.

Requests varied their body per iteration (`{"n": <i>}`) — sending the exact
same request repeatedly trips wardn's own loop/runaway detector (P1.5),
correctly, since that's indistinguishable from a stuck agent. That's a
feature, not a benchmark artifact, but it means identical-body benchmarking
would measure the loop guard's block path, not the proxy's real per-request
overhead.

**Environment:** AMD Ryzen 7 7435HS, 16 threads, Linux 7.1, localhost-only
(127.0.0.1), release build (`cargo build --release`). This is a single
machine, single run — treat the numbers as "order of magnitude and shape,"
not a guaranteed SLA. Re-run `scripts/bench-proxy-overhead.sh` (below) on
your own hardware for numbers specific to your setup.

## Results (n=30 each)

| | Direct (no proxy) | Through wardn | Overhead |
|---|---|---|---|
| Plain JSON — median TTFB | 0.592ms | 1.120ms | **+0.53ms** |
| Plain JSON — median total | 0.644ms | 1.210ms | **+0.57ms** |
| SSE streaming — median TTFB (≈TTFT) | 0.635ms | 1.031ms | **+0.40ms** |
| SSE streaming — median total | 51.504ms | 51.951ms | **+0.45ms** |
| Plain JSON — p90 TTFB | 0.665ms | 1.437ms | +0.77ms |

## Reading the numbers

- **The added latency is sub-millisecond and doesn't scale with response
  size.** The streaming case's *total* time is ~51ms either way (dominated
  by the simulated token-generation delay) — wardn's overhead shows up once,
  at connection setup / first-byte, not per chunk. The streaming stripper
  (P0.3/P2.3) processes each chunk as it arrives rather than buffering, so
  it doesn't add per-chunk latency.
- **This is a lower bound, not an upper bound.** A real deployment adds:
  real network RTT to the actual API (same with or without wardn — it's not
  wardn's overhead), TLS handshake to the real upstream (again, identical
  either way since wardn itself terminates plaintext-locally and
  re-establishes its own TLS connection to the real API — see
  `reqwest`/`rustls` in Cargo.toml), and OS scheduling noise under real
  concurrent load. What this benchmark isolates is specifically *wardn's own
  processing time* — vault read lock, placeholder→credential resolution,
  domain/budget/loop checks, and re-streaming.
- **Where the time actually goes:** an extra TCP hop (agent → wardn → real
  API instead of agent → real API directly) is the majority of the added
  time at this scale — sub-millisecond on loopback, and in the low
  single-digit milliseconds on a real deployment where wardn runs as a local
  subprocess (still on loopback in the common case: IDE spawns `wardn serve`
  on `127.0.0.1`).

## Reproducing this

```bash
cargo build --release --features test-fast-kdf
./scripts/bench-proxy-overhead.sh
```

The script builds its own throwaway vault, a local mock upstream, and a
`wardn serve` instance wired to it via a custom `[warden.upstreams]` slug,
then runs the same direct-vs-proxy comparison above and prints the medians.
Set `BENCH_N=100` to run more samples per case.
