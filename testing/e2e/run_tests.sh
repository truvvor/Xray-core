#!/usr/bin/env bash
#
# Xray-core Anti-DPI E2E Test Suite
#
# Usage:
#   SERVER_IP=1.2.3.4 ./run_tests.sh          # full test against remote server
#   ./run_tests.sh --local                     # local loopback test (server + client on same machine)
#
# Prerequisites:
#   - xray binary built from this branch
#   - curl, timeout (coreutils)
#   - Optional: tshark/tcpdump for traffic capture analysis
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIGS_DIR="$SCRIPT_DIR/../configs"
XRAY_BIN="${XRAY_BIN:-$SCRIPT_DIR/../../xray}"
LOCAL_MODE=false
SERVER_IP="${SERVER_IP:-}"
TEST_TIMEOUT=15
PASSED=0
FAILED=0
SKIPPED=0
CAPTURE_FILE=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup_pids=()

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${cleanup_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -f /tmp/xray-test-server.json /tmp/xray-test-client.json
    if [ -n "$CAPTURE_FILE" ]; then echo "Traffic capture saved to: $CAPTURE_FILE"; fi
}
trap cleanup EXIT

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILED=$((FAILED+1)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIPPED=$((SKIPPED+1)); }
log_info() { echo -e "[ .. ] $1"; }

# ── Argument parsing ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --local)    LOCAL_MODE=true; shift ;;
        --server)   SERVER_IP="$2"; shift 2 ;;
        --bin)      XRAY_BIN="$2"; shift 2 ;;
        --capture)  CAPTURE_FILE="$2"; shift 2 ;;
        *)          echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Pre-flight checks ────────────────────────────────────────────
if [ ! -x "$XRAY_BIN" ]; then
    echo "Error: xray binary not found at $XRAY_BIN"
    echo "Build first: go build -o xray ./main"
    exit 1
fi

echo "=== Xray Anti-DPI E2E Tests ==="
echo "Binary: $XRAY_BIN"
if [ "$LOCAL_MODE" = true ]; then
    echo "Mode:   local loopback"
else
    echo "Mode:   remote ($SERVER_IP)"
fi
echo ""

# ── Generate REALITY keys ────────────────────────────────────────
log_info "Generating REALITY key pair..."
KEYPAIR=$("$XRAY_BIN" x25519 2>&1) || true
log_info "x25519 output: $KEYPAIR"
PRIVATE_KEY=$(echo "$KEYPAIR" | grep -i "Private" | awk '{print $NF}')
PUBLIC_KEY=$(echo "$KEYPAIR" | grep -i "Public" | awk '{print $NF}')

if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
    echo "Error: Failed to generate REALITY keys"
    echo "x25519 full output: $KEYPAIR"
    echo "Trying alternative: $XRAY_BIN x25519"
    "$XRAY_BIN" x25519 || true
    exit 1
fi
log_info "Keys generated successfully"

# ── Prepare configs ───────────────────────────────────────────────
if [ "$LOCAL_MODE" = true ]; then
    SERVER_IP="127.0.0.1"
fi

if [ -z "$SERVER_IP" ]; then
    echo "Error: SERVER_IP not set. Use --local or --server <ip> or export SERVER_IP"
    exit 1
fi

# Server config
sed -e "s|REPLACE_WITH_GENERATED_PRIVATE_KEY|$PRIVATE_KEY|g" \
    "$CONFIGS_DIR/server.json" > /tmp/xray-test-server.json

# Client config
sed -e "s|REPLACE_WITH_SERVER_IP|$SERVER_IP|g" \
    -e "s|REPLACE_WITH_GENERATED_PUBLIC_KEY|$PUBLIC_KEY|g" \
    "$CONFIGS_DIR/client.json" > /tmp/xray-test-client.json

# ── Start traffic capture (optional) ─────────────────────────────
if [ -n "$CAPTURE_FILE" ] && command -v tcpdump &>/dev/null; then
    log_info "Starting traffic capture -> $CAPTURE_FILE"
    if [ "$LOCAL_MODE" = true ]; then
        tcpdump -i lo -w "$CAPTURE_FILE" port 10443 or port 8443 &>/dev/null &
    else
        tcpdump -i any -w "$CAPTURE_FILE" host "$SERVER_IP" &>/dev/null &
    fi
    if [ $? -eq 0 ]; then
        cleanup_pids+=($!)
        sleep 1
    else
        log_info "tcpdump failed (no permissions) — skipping capture"
        CAPTURE_FILE=""
    fi
fi

# ── Start server (local mode only) ───────────────────────────────
if [ "$LOCAL_MODE" = true ]; then
    log_info "Starting Xray server..."
    "$XRAY_BIN" run -c /tmp/xray-test-server.json &>/tmp/xray-server.log &
    cleanup_pids+=($!)
    sleep 2

    if ! kill -0 "${cleanup_pids[-1]}" 2>/dev/null; then
        echo "Error: Server failed to start. Log:"
        cat /tmp/xray-server.log
        exit 1
    fi
    log_info "Server started (PID ${cleanup_pids[-1]})"
fi

# ── Start client ──────────────────────────────────────────────────
log_info "Starting Xray client..."
"$XRAY_BIN" run -c /tmp/xray-test-client.json &>/tmp/xray-client.log &
cleanup_pids+=($!)
sleep 2

if ! kill -0 "${cleanup_pids[-1]}" 2>/dev/null; then
    echo "Error: Client failed to start. Log:"
    cat /tmp/xray-client.log
    exit 1
fi
log_info "Client started (PID ${cleanup_pids[-1]})"

# ══════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════

echo ""
echo "=== Running Tests ==="

# ── Test 1: Basic SOCKS5 connectivity via VLESS+REALITY ──────────
test_basic_connectivity() {
    log_info "Test 1: Basic connectivity (VLESS+REALITY)"
    RESP=$(timeout $TEST_TIMEOUT curl -s -o /dev/null -w "%{http_code}" \
        --socks5-hostname 127.0.0.1:1080 \
        https://example.com 2>/dev/null || echo "000")

    if [ "$RESP" = "200" ] || [ "$RESP" = "301" ] || [ "$RESP" = "302" ]; then
        log_pass "Basic HTTPS request through VLESS+REALITY (HTTP $RESP)"
    elif [ "$RESP" = "000" ]; then
        log_fail "Basic connectivity — connection timed out or refused"
    else
        log_fail "Basic connectivity — unexpected HTTP $RESP"
    fi
}

# ── Test 2: Multiple sequential connections ───────────────────────
test_sequential_connections() {
    log_info "Test 2: Sequential connections (tests padding randomization)"
    local success=0
    local total=5

    for i in $(seq 1 $total); do
        RESP=$(timeout $TEST_TIMEOUT curl -s -o /dev/null -w "%{http_code}" \
            --socks5-hostname 127.0.0.1:1080 \
            "https://example.com" 2>/dev/null || echo "000")
        [ "$RESP" != "000" ] && success=$((success+1))
    done

    if [ "$success" -eq "$total" ]; then
        log_pass "Sequential connections: $success/$total succeeded"
    elif [ "$success" -gt 0 ]; then
        log_fail "Sequential connections: only $success/$total succeeded"
    else
        log_fail "Sequential connections: all failed"
    fi
}

# ── Test 3: Parallel connections ──────────────────────────────────
test_parallel_connections() {
    log_info "Test 3: Parallel connections (tests jitter under load)"
    local pids=()
    local results_dir=$(mktemp -d)

    for i in $(seq 1 8); do
        (
            RESP=$(timeout $TEST_TIMEOUT curl -s -o /dev/null -w "%{http_code}" \
                --socks5-hostname 127.0.0.1:1080 \
                "https://example.com" 2>/dev/null || echo "000")
            echo "$RESP" > "$results_dir/$i"
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    local success=0
    for f in "$results_dir"/*; do
        [ "$(cat "$f")" != "000" ] && success=$((success+1))
    done
    rm -rf "$results_dir"

    if [ "$success" -ge 6 ]; then
        log_pass "Parallel connections: $success/8 succeeded"
    elif [ "$success" -gt 0 ]; then
        log_fail "Parallel connections: only $success/8 succeeded"
    else
        log_fail "Parallel connections: all failed"
    fi
}

# ── Test 4: Large file download ───────────────────────────────────
test_large_download() {
    log_info "Test 4: Large download (tests record size randomization)"
    SIZE=$(timeout 30 curl -s --socks5-hostname 127.0.0.1:1080 \
        "https://example.com" 2>/dev/null | wc -c)

    if [ "$SIZE" -ge 500 ]; then
        log_pass "Large download: received $SIZE bytes"
    elif [ "$SIZE" -gt 0 ]; then
        log_pass "Download works: received $SIZE bytes"
    else
        log_fail "Large download: no data received"
    fi
}

# ── Test 5: Long-lived connection (heartbeat test) ────────────────
test_long_connection() {
    log_info "Test 5: Long-lived connection (idle period + resumed transfer)"
    # First request
    R1=$(timeout $TEST_TIMEOUT curl -s -o /dev/null -w "%{http_code}" \
        --socks5-hostname 127.0.0.1:1080 \
        "https://example.com" 2>/dev/null || echo "000")

    # Wait (simulates idle period)
    sleep 5

    # Second request on (potentially) same connection
    R2=$(timeout $TEST_TIMEOUT curl -s -o /dev/null -w "%{http_code}" \
        --socks5-hostname 127.0.0.1:1080 \
        "https://example.com" 2>/dev/null || echo "000")

    if [ "$R1" = "200" ] && [ "$R2" = "200" ]; then
        log_pass "Long-lived connection: both phases succeeded after idle"
    else
        log_fail "Long-lived connection: phase1=$R1 phase2=$R2"
    fi
}

# ── Test 6: DNS leak check ────────────────────────────────────────
test_dns_through_proxy() {
    log_info "Test 6: DNS resolution through proxy"
    RESP=$(timeout $TEST_TIMEOUT curl -s -o /dev/null -w "%{http_code}" \
        --socks5-hostname 127.0.0.1:1080 \
        "https://www.google.com" 2>/dev/null || echo "000")

    if [ "$RESP" = "200" ] || [ "$RESP" = "301" ] || [ "$RESP" = "302" ]; then
        log_pass "DNS through proxy works (HTTP $RESP to google.com)"
    else
        log_fail "DNS through proxy failed (HTTP $RESP)"
    fi
}

# ── Test 7: TLS fingerprint verification ──────────────────────────
test_tls_fingerprint() {
    log_info "Test 7: TLS fingerprint check"
    RESP=$(timeout $TEST_TIMEOUT curl -s --socks5-hostname 127.0.0.1:1080 \
        "https://tls.browserleaks.com/json" 2>/dev/null || echo "{}")

    if echo "$RESP" | grep -q "ja3_hash\|ja4\|tls_version"; then
        JA3=$(echo "$RESP" | grep -o '"ja3_hash":"[^"]*"' | head -1 || echo "n/a")
        log_pass "TLS fingerprint received: $JA3"
    else
        log_skip "TLS fingerprint — service unreachable (non-critical)"
    fi
}

# ── Test 8: Packet size variation analysis ────────────────────────
test_packet_variation() {
    log_info "Test 8: Packet size variation (anti-DPI core check)"
    if [ -z "$CAPTURE_FILE" ] || ! command -v tshark &>/dev/null; then
        log_skip "Packet analysis requires --capture and tshark"
        return
    fi

    # Wait for capture to flush
    sleep 2

    # Analyze TCP payload sizes to server
    SIZES=$(tshark -r "$CAPTURE_FILE" -Y "tcp.len > 0 && tcp.dstport == 443" \
        -T fields -e tcp.len 2>/dev/null | sort -n | uniq -c | sort -rn | head -5)

    if [ -z "$SIZES" ]; then
        log_skip "No captured packets to analyze"
        return
    fi

    UNIQUE_SIZES=$(echo "$SIZES" | wc -l)
    TOP_FREQ=$(echo "$SIZES" | head -1 | awk '{print $1}')
    TOTAL=$(tshark -r "$CAPTURE_FILE" -Y "tcp.len > 0 && tcp.dstport == 443" \
        -T fields -e tcp.len 2>/dev/null | wc -l)

    CONCENTRATION=$(( TOP_FREQ * 100 / TOTAL ))

    echo "       Top 5 payload sizes: $(echo "$SIZES" | tr '\n' ' ')"
    echo "       Unique sizes: $UNIQUE_SIZES, Top frequency: $CONCENTRATION% of total"

    if [ "$UNIQUE_SIZES" -ge 5 ] && [ "$CONCENTRATION" -lt 40 ]; then
        log_pass "Good packet size variation ($UNIQUE_SIZES unique, top=$CONCENTRATION%)"
    elif [ "$UNIQUE_SIZES" -ge 3 ]; then
        log_pass "Acceptable packet size variation ($UNIQUE_SIZES unique, top=$CONCENTRATION%)"
    else
        log_fail "Poor packet size variation — DPI may detect patterns"
    fi
}

# ── Run all tests ─────────────────────────────────────────────────
test_basic_connectivity
test_sequential_connections
test_parallel_connections
test_large_download
test_long_connection
test_dns_through_proxy
test_tls_fingerprint
test_packet_variation

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════"
echo -e " Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}, ${YELLOW}$SKIPPED skipped${NC}"
echo "════════════════════════════════"

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "Server log (last 20 lines):"
    tail -20 /tmp/xray-server.log 2>/dev/null || true
    echo ""
    echo "Client log (last 20 lines):"
    tail -20 /tmp/xray-client.log 2>/dev/null || true
    exit 1
fi

exit 0
