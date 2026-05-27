#!/usr/bin/env bash
# PayloadGuard eBPF agent — PC smoke test
# Run this on a Linux machine with CONFIG_KPROBES=y (standard Ubuntu/Fedora/WSL2)
#
# Usage:
#   sudo bash scripts/pc-smoke-test.sh [--mode audit|block] [--policy path/to/policy.yaml]
#
# What it does:
#   1. Builds the agent binary (requires Go + clang + libbpf-dev)
#   2. Launches agent in the background (audit mode by default)
#   3. Fires all 4 event types: execve, egress connect, ptrace, /proc/mem open
#   4. Kills the agent and prints the captured events
#   5. Exits 0 if at least one event of each type was captured

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_DIR="$REPO_ROOT/agent"
DIST_DIR="$REPO_ROOT/dist"
EVENTS_FILE="/tmp/pg-smoke-events.json"
MODE="${1:-audit}"
POLICY=""

# Parse flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)    MODE="$2";   shift 2 ;;
        --policy)  POLICY="$2"; shift 2 ;;
        *)         shift ;;
    esac
done

# ── 1. Build ─────────────────────────────────────────────────────────────────
echo "==> Installing build deps (libbpf-dev if absent)..."
if ! dpkg -l libbpf-dev &>/dev/null 2>&1; then
    apt install -y libbpf-dev linux-headers-generic 2>/dev/null || \
    apt install -y --fix-missing libbpf-dev 2>/dev/null || true
fi

echo "==> Building pg-agent..."
cd "$AGENT_DIR"
go generate ./...
GOOS=linux GOARCH=amd64 go build -o "$DIST_DIR/pg-agent-linux-amd64" .
echo "    Binary: $DIST_DIR/pg-agent-linux-amd64"

# ── 2. Launch agent ───────────────────────────────────────────────────────────
echo "==> Starting agent in $MODE mode..."
rm -f "$EVENTS_FILE"
POLICY_FLAG=""
[[ -n "$POLICY" ]] && POLICY_FLAG="--policy=$POLICY"

"$DIST_DIR/pg-agent-linux-amd64" \
    --mode="$MODE" \
    --dry-run \
    --out="$EVENTS_FILE" \
    $POLICY_FLAG &
AGENT_PID=$!
echo "    Agent PID: $AGENT_PID"
sleep 1  # let agent attach tracepoints

# ── 3. Trigger events ─────────────────────────────────────────────────────────
echo "==> Firing test events..."

# RT01 — procmem open (own PID, safe)
echo "    [RT01] /proc/self/mem open"
python3 -c "
import os
fd = os.open('/proc/self/mem', os.O_RDONLY)
os.close(fd)
" 2>/dev/null || true

# RT02 — egress connect to loopback (always allowed)
echo "    [RT02] egress connect to 127.0.0.1"
curl -s --connect-timeout 1 http://127.0.0.1:9999 2>/dev/null || true

# RT03 — ptrace self (PTRACE_TRACEME)
echo "    [RT03] PTRACE_TRACEME self-attach"
python3 -c "
import ctypes
libc = ctypes.CDLL('libc.so.6', use_errno=True)
libc.ptrace(0, 0, 0, 0)
" 2>/dev/null || true

# execve — any command will trigger it
echo "    [EXECVE] spawning /bin/true"
/bin/true || true

sleep 1  # let events flush to ringbuf

# ── 4. Stop agent ─────────────────────────────────────────────────────────────
echo "==> Stopping agent..."
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

# ── 5. Check results ──────────────────────────────────────────────────────────
echo ""
echo "==> Captured events:"
if [[ -f "$EVENTS_FILE" ]]; then
    cat "$EVENTS_FILE"
    echo ""
    TOTAL=$(wc -l < "$EVENTS_FILE")
    echo "    Total events: $TOTAL"
    PASS=true
    for TYPE in execve egress_connect ptrace_attach procmem_open; do
        if grep -q "\"$TYPE\"" "$EVENTS_FILE"; then
            echo "    ✓ $TYPE"
        else
            echo "    ✗ $TYPE (not captured)"
            PASS=false
        fi
    done
    echo ""
    if $PASS; then
        echo "SMOKE TEST PASSED — all 4 event types captured"
        exit 0
    else
        echo "SMOKE TEST INCOMPLETE — some event types missing (kernel may filter them)"
        exit 1
    fi
else
    echo "No events file produced."
    echo ""
    echo "If preflight warning appeared above, your kernel lacks CONFIG_KPROBES."
    echo "Check: zcat /proc/config.gz | grep CONFIG_KPROBES"
    exit 1
fi
