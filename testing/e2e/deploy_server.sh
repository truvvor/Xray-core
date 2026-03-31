#!/usr/bin/env bash
#
# Deploy Xray server to a remote machine
#
# Usage:
#   ./deploy_server.sh user@server-ip [--key ~/.ssh/id_rsa]
#
# Prerequisites:
#   - SSH access to the server
#   - xray binary already built (go build -o xray ./main)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$SCRIPT_DIR/../.."
XRAY_BIN="${XRAY_BIN:-$REPO_DIR/xray}"
SSH_KEY=""
REMOTE_DIR="/opt/xray-test"

if [ $# -lt 1 ]; then
    echo "Usage: $0 user@server-ip [--key ~/.ssh/id_rsa]"
    exit 1
fi

REMOTE_HOST="$1"; shift
while [[ $# -gt 0 ]]; do
    case $1 in
        --key) SSH_KEY="-i $2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

SSH_CMD="ssh $SSH_KEY"
SCP_CMD="scp $SSH_KEY"

# ── Build if needed ───────────────────────────────────────────────
if [ ! -f "$XRAY_BIN" ]; then
    echo "Building xray binary..."
    cd "$REPO_DIR"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o xray ./main
fi

# ── Generate keys ────────────────────────────────────────────────
echo "Generating REALITY keys..."
KEYPAIR=$("$XRAY_BIN" x25519 2>/dev/null)
PRIVATE_KEY=$(echo "$KEYPAIR" | grep "Private" | awk '{print $3}')
PUBLIC_KEY=$(echo "$KEYPAIR" | grep "Public" | awk '{print $3}')
echo "Public key (save this for client config): $PUBLIC_KEY"

# ── Prepare server config ────────────────────────────────────────
sed "s|REPLACE_WITH_GENERATED_PRIVATE_KEY|$PRIVATE_KEY|g" \
    "$SCRIPT_DIR/../configs/server.json" > /tmp/xray-deploy-server.json

# ── Deploy ────────────────────────────────────────────────────────
echo "Deploying to $REMOTE_HOST..."

$SSH_CMD "$REMOTE_HOST" "mkdir -p $REMOTE_DIR && systemctl stop xray-test 2>/dev/null || true"

$SCP_CMD "$XRAY_BIN" "$REMOTE_HOST:$REMOTE_DIR/xray"
$SCP_CMD /tmp/xray-deploy-server.json "$REMOTE_HOST:$REMOTE_DIR/config.json"

# ── Create systemd service ────────────────────────────────────────
$SSH_CMD "$REMOTE_HOST" bash <<'REMOTE_SCRIPT'
chmod +x /opt/xray-test/xray

cat > /etc/systemd/system/xray-test.service <<EOF
[Unit]
Description=Xray Anti-DPI Test Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/xray-test/xray run -c /opt/xray-test/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray-test
systemctl restart xray-test
sleep 2
systemctl status xray-test --no-pager
REMOTE_SCRIPT

echo ""
echo "════════════════════════════════════════════════"
echo " Server deployed successfully!"
echo ""
echo " To run tests from client machine:"
echo "   SERVER_IP=$(echo $REMOTE_HOST | cut -d@ -f2) ./run_tests.sh"
echo ""
echo " Client config needs:"
echo "   publicKey: $PUBLIC_KEY"
echo "   serverIP:  $(echo $REMOTE_HOST | cut -d@ -f2)"
echo "════════════════════════════════════════════════"

rm -f /tmp/xray-deploy-server.json
