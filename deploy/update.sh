#!/usr/bin/env bash
# Update an existing msg.lmm.best installation.
# Usage: bash deploy/update.sh [ssh-host]
set -euo pipefail

HOST="${1:-archczy}"
DOMAIN="msg.lmm.best"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="/tmp/msg-lmm-best-update.$$"

cd "$ROOT"

for cmd in uv ssh; do
    command -v "$cmd" >/dev/null || {
        echo "error: $cmd is required locally" >&2
        exit 1
    }
done

echo "==> lint"
uv run ruff check src tests
uv run ruff format --check src tests

echo "==> test"
uv run python -m unittest discover -s tests -q

echo "==> build"
rm -rf dist
uv build --wheel --quiet
WHEEL="$(basename dist/*.whl)"

echo "==> upload"
ssh "$HOST" "rm -rf '$STAGE' && mkdir -p '$STAGE'"
tar -C "$ROOT" -cf - \
    "dist/$WHEEL" \
    deploy/msg-lmm-best.service \
    deploy/nginx/nginx.conf \
    deploy/nginx/msg.lmm.best.conf \
    deploy/nginx/msg.lmm.best.proxy.conf \
    | ssh "$HOST" "tar -C '$STAGE' -xf -"

echo "==> update $HOST"
ssh "$HOST" STAGE="$STAGE" WHEEL="$WHEEL" 'bash -s' <<'REMOTE'
set -euo pipefail
trap 'rm -rf "$STAGE"' EXIT

VENV=/opt/msg-lmm-best/venv
CONFIG=/etc/msg-lmm-best/msg.conf
SERVICE=msg-lmm-best.service
D="$STAGE/deploy"

test -f "$CONFIG" || {
    echo "error: msgd config not found; use deploy/deploy.sh for a fresh install" >&2
    exit 1
}
systemctl cat "$SERVICE" >/dev/null 2>&1 || {
    echo "error: msgd systemd unit not found; use deploy/deploy.sh for a fresh install" >&2
    exit 1
}
command -v uv >/dev/null || {
    echo "error: uv is not installed on the server" >&2
    exit 1
}

echo "==> Valkey"
sudo pacman -S --needed --noconfirm valkey git
sudo systemctl enable --now valkey.service
test -x /usr/bin/python3 || {
    echo "error: /usr/bin/python3 is missing" >&2
    exit 1
}
/usr/bin/python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 14))' || {
    echo "error: system Python 3.14+ is required; update the server packages first" >&2
    exit 1
}

if ! test -x "$VENV/bin/python" || ! "$VENV/bin/python" -c     'import sys; raise SystemExit(sys.version_info < (3, 14))'; then
    echo "==> migrate venv to Python 3.14"
    sudo systemctl stop "$SERVICE"
    sudo rm -rf "$VENV"
    sudo uv venv --quiet --python /usr/bin/python3 "$VENV"
fi

echo "==> install package"
sudo UV_NO_CACHE=1 uv pip install --quiet \
    --python "$VENV/bin/python" \
    --reinstall --compile-bytecode \
    "$STAGE/dist/$WHEEL"

echo "==> root CA"
sudo "$VENV/bin/msgd-cert" init-root

if ! sudo grep -q '^\[analytics\]' "$CONFIG"; then
    echo "==> enable Valkey analytics"
    sudo tee -a "$CONFIG" >/dev/null <<'EOF'

[analytics]
valkey_url = redis://127.0.0.1:6379/0
valkey_prefix = msgd
valkey_required = true
EOF
fi

if ! sudo grep -q '^\[repos\]' "$CONFIG"; then
    echo "==> enable public Git repositories"
    sudo tee -a "$CONFIG" >/dev/null <<'EOF'

[repos]
root = /var/lib/msg-lmm-best/repos
max_blob_bytes = 1048576
auth_ttl_seconds = 300
max_request_bytes = 67108864
EOF
fi

if ! sudo grep -q '^\[websub\]' "$CONFIG"; then
    echo "==> enable WebSub hubs"
    sudo tee -a "$CONFIG" >/dev/null <<'EOF'

[websub]
delivery_enabled = true
default_lease_seconds = 864000
max_lease_seconds = 2592000
external_hubs = https://websubhub.com/hub,https://pubsubhubbub.appspot.com/
EOF
elif ! sudo grep -q '^external_hubs[[:space:]]*=' "$CONFIG"; then
    echo "==> enable external WebSub hubs"
    sudo sed -i '/^\[websub\]/a external_hubs = https://websubhub.com/hub,https://pubsubhubbub.appspot.com/' "$CONFIG"
fi

echo "==> validate"
"$VENV/bin/msgd" --config "$CONFIG" --check
sudo rm -f /usr/local/bin/msgd-admin
sudo ln -sfn "$VENV/bin/msgdctl" /usr/local/bin/msgdctl
sudo ln -sfn "$VENV/bin/msgd-cert" /usr/local/bin/msgd-cert

echo "==> systemd"
sudo install -m 0644 "$D/msg-lmm-best.service" \
    /etc/systemd/system/msg-lmm-best.service
sudo systemctl disable --now msg-lmm-best-index.timer >/dev/null 2>&1 || true
sudo rm -f /etc/systemd/system/msg-lmm-best-index.timer \
    /etc/systemd/system/msg-lmm-best-index.service
sudo systemctl daemon-reload

echo "==> restart"
sudo systemctl restart "$SERVICE"

for _ in $(seq 1 50); do
    if curl -fsS http://127.0.0.1:3111/_health >/dev/null; then
        break
    fi
    sleep 0.2
done
curl -fsS http://127.0.0.1:3111/_health


echo "==> nginx request/path limits"
sudo install -m 0644 "$D/nginx/nginx.conf" /etc/nginx/nginx.conf
sed 's/^#TLS# \{0,1\}//' "$D/nginx/msg.lmm.best.conf" \
    | sudo tee /etc/nginx/conf.d/msg.lmm.best.conf >/dev/null
sudo install -m 0644 "$D/nginx/msg.lmm.best.proxy.conf" \
    /etc/nginx/msg.lmm.best.proxy.conf
sudo nginx -t
sudo systemctl reload nginx
REMOTE

echo "==> public health"
curl -fsS "https://$DOMAIN/_health"
echo
echo "==> updated"
