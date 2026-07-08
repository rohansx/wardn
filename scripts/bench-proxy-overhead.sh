#!/bin/sh
# Measures wardn's own proxy-hop overhead against a local mock upstream —
# see docs/benchmarks.md for methodology and how to read the results.
#
# Requires: a release build (cargo build --release --features test-fast-kdf),
# python3, curl, awk.
set -e

WARDN_BIN="${WARDN_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/wardn}"
N="${BENCH_N:-30}"
WORKDIR="$(mktemp -d)"
trap 'kill $MOCK_PID $PROXY_PID 2>/dev/null; rm -rf "$WORKDIR"' EXIT

if [ ! -x "$WARDN_BIN" ]; then
    echo "error: $WARDN_BIN not found — run: cargo build --release --features test-fast-kdf" >&2
    exit 1
fi

cat > "$WORKDIR/mock_upstream.py" <<'PYEOF'
import http.server, socketserver, time

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.path.endswith("/stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for i in range(5):
                self.wfile.write(f'data: {{"delta":"chunk-{i}"}}\n\n'.encode())
                self.wfile.flush()
                time.sleep(0.01)
            self.wfile.write(b"data: [DONE]\n\n")
        else:
            body = b'{"id":"msg_bench","content":[{"type":"text","text":"ok"}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

Server(("127.0.0.1", 9100), Handler).serve_forever()
PYEOF

cat > "$WORKDIR/wardn.toml" <<'EOF'
[warden.upstreams]
bench = "http://127.0.0.1:9100"
EOF

python3 "$WORKDIR/mock_upstream.py" > "$WORKDIR/mock.log" 2>&1 &
MOCK_PID=$!
sleep 0.5

WARDN_PASSPHRASE=benchpass "$WARDN_BIN" --vault "$WORKDIR/vault.enc" vault create >/dev/null
WARDN_PASSPHRASE=benchpass WARDN_VALUE=fake-bench-key-1234567890 \
    "$WARDN_BIN" --vault "$WORKDIR/vault.enc" vault set BENCH_KEY --domain 127.0.0.1 >/dev/null
PLACEHOLDER=$(WARDN_PASSPHRASE=benchpass "$WARDN_BIN" --vault "$WORKDIR/vault.enc" vault get BENCH_KEY --agent bench-agent)

WARDN_PASSPHRASE=benchpass "$WARDN_BIN" --vault "$WORKDIR/vault.enc" --config "$WORKDIR/wardn.toml" \
    serve --port 7777 > "$WORKDIR/proxy.log" 2>&1 &
PROXY_PID=$!
sleep 0.5

bench() {
    url="$1"; via_proxy="$2"
    i=0
    while [ "$i" -lt "$N" ]; do
        if [ "$via_proxy" = "1" ]; then
            curl -sS -o /dev/null -w '%{time_starttransfer} %{time_total} %{http_code}\n' \
                -X POST "$url" \
                -H "x-warden-agent: bench-agent" \
                -H "Authorization: Bearer ${PLACEHOLDER}" \
                -d "{\"n\":$i}"
        else
            curl -sS -o /dev/null -w '%{time_starttransfer} %{time_total} %{http_code}\n' \
                -X POST "$url" -d "{\"n\":$i}"
        fi
        i=$((i + 1))
    done
}

analyze() {
    label="$1"
    awk -v label="$label" '{ttfb[NR]=$1*1000; total[NR]=$2*1000} END {
        n=NR
        for(i=1;i<=n;i++) for(j=i+1;j<=n;j++) if(ttfb[i]>ttfb[j]){t=ttfb[i];ttfb[i]=ttfb[j];ttfb[j]=t}
        for(i=1;i<=n;i++) for(j=i+1;j<=n;j++) if(total[i]>total[j]){t=total[i];total[i]=total[j];total[j]=t}
        med_ttfb = (n%2==1) ? ttfb[(n+1)/2] : (ttfb[n/2]+ttfb[n/2+1])/2
        med_total = (n%2==1) ? total[(n+1)/2] : (total[n/2]+total[n/2+1])/2
        printf "%-24s n=%-4d median_ttfb=%.3fms  median_total=%.3fms\n", label, n, med_ttfb, med_total
    }'
}

echo "warming up..."
bench "http://127.0.0.1:9100/v1/messages" 0 >/dev/null

echo ""
echo "results (n=${N}):"
bench "http://127.0.0.1:9100/v1/messages" 0 | analyze "direct (json)"
bench "http://127.0.0.1:7777/bench/v1/messages" 1 | analyze "wardn proxy (json)"
bench "http://127.0.0.1:9100/v1/messages/stream" 0 | analyze "direct (stream)"
bench "http://127.0.0.1:7777/bench/v1/messages/stream" 1 | analyze "wardn proxy (stream)"
