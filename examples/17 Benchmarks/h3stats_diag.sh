#!/bin/sh
# H3 stats diagnostic
#
# Drives a series of H3 requests against the example 17 server
# and snapshots /h3stats after each one, both live (live
# connections only) and via ?keep=1 (live + recently-reaped).
#
# Why both: a working request typically finishes and gets
# reaped before /h3stats can run, so the "live" snapshot is
# usually empty or shows only orphan handshake attempts. The
# ?keep=1 snapshot captures the just-reaped connection's final
# stats, which is what we actually want to inspect for perf
# diagnosis (cwnd at end of transfer, total bytes sent, RTT,
# delivery_rate).
#
# Usage:
#   cd "examples/17 Benchmarks"
#   php index.php   # in another terminal
#   sh h3stats_diag.sh
#
# By default uses /opt/homebrew/opt/curl/bin/curl (Homebrew
# curl with H3 enabled). Override CURL=/path/to/curl if needed.
# The H3 server is expected at https://localhost:8443/, the
# admin server at http://localhost:8080/.

CURL="${CURL:-/opt/homebrew/opt/curl/bin/curl}"
H3_BASE="${H3_BASE:-https://localhost:8443}"
ADMIN_BASE="${ADMIN_BASE:-http://localhost:8080}"

if [ ! -x "$CURL" ]; then
    echo "Error: curl with H3 support not found at $CURL"
    echo "Install via 'brew install curl' or override:"
    echo "  CURL=/path/to/h3-curl sh $0"
    exit 1
fi

if ! "$CURL" -k --http3-only -s -o /dev/null \
        --max-time 5 "$H3_BASE/small"; then
    echo "Error: H3 request failed. Is the server running?"
    echo "Start with: php index.php (in 'examples/17 Benchmarks/')"
    exit 1
fi

snapshot() {
    label="$1"
    keep="$2"
    url="$ADMIN_BASE/h3stats"
    if [ "$keep" = "yes" ]; then
        url="$url?keep=1"
    fi
    echo "===================================================="
    echo "  $label"
    echo "  GET $url"
    echo "===================================================="
    curl -s "$url"
    echo
    echo
}

drive_h3() {
    label="$1"
    path="$2"
    echo
    echo ">>> driving H3 request: $path  ($label)"
    "$CURL" -k --http3-only -s -o /dev/null "$H3_BASE$path"
}

echo
echo "===================================================="
echo "STAGE 0: baseline (before any H3 traffic)"
echo "===================================================="
snapshot "stats (baseline)" no

drive_h3 "warmup small request" "/small"
sleep 0.5
snapshot "stats after /small (live + reaped)" yes

drive_h3 "1 MiB body" "/big"
sleep 0.5
snapshot "stats after /big (live + reaped)" yes

echo ">>> driving 10 sequential /big requests to let cwnd ramp"
for i in 1 2 3 4 5 6 7 8 9 10; do
    "$CURL" -k --http3-only -s -o /dev/null "$H3_BASE/big"
done
sleep 0.5
snapshot "stats after 10x /big (live + reaped)" yes

echo "===================================================="
echo "Done. The 'reaped' arrays in the ?keep=1 responses"
echo "show the final stats of each completed connection."
echo "Look at:"
echo "  - cwnd: should grow to MB-scale on a long transfer"
echo "  - rtt_ms: should be sub-millisecond on localhost"
echo "  - delivery_rate: bytes/sec quiche measured"
echo "  - lost / retrans: should be 0 on localhost"
echo "  - state == 'closed' or 'draining': orderly shutdown"
echo "  - state == 'pending' with reason 'stale_handshake':"
echo "    abandoned curl race candidate (expected, harmless)"
echo "===================================================="
