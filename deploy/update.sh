#!/usr/bin/env bash
# Update an existing msg.lmm.best installation.
# Usage: bash deploy/update.sh [ssh-host]
set -euo pipefail

HOST="${1:-archczy}"
DOMAIN="msg.lmm.best"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_WHEEL="/tmp/msg-lmm-best-update.whl"

cd "$ROOT"

for cmd in python3 uv ssh scp; do
    command -v "$cmd" >/dev/null || {
        echo "error: $cmd is required locally" >&2
        exit 1
    }
done

echo "==> test"
PYTHONPATH=src python3 -m unittest discover -s tests -q

echo "==> build"
rm -rf dist
uv build --wheel --quiet
WHEEL="$(printf '%s\n' dist/*.whl | head -n1)"

echo "==> upload"
scp "$WHEEL" "$HOST:$REMOTE_WHEEL"

echo "==> update $HOST"
ssh "$HOST" REMOTE_WHEEL="$REMOTE_WHEEL" 'bash -s' <<'REMOTE'
set -euo pipefail
trap 'rm -f "$REMOTE_WHEEL"' EXIT

VENV=/opt/msg-lmm-best/venv
CONFIG=/etc/msg-lmm-best/msg.conf
SERVICE=msg-lmm-best.service

test -x "$VENV/bin/python" || {
    echo "error: msgd venv not found; use deploy/deploy.sh for a fresh install" >&2
    exit 1
}
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

echo "==> install package"
sudo UV_NO_CACHE=1 uv pip install --quiet     --python "$VENV/bin/python"     --reinstall --no-deps --compile-bytecode     "$REMOTE_WHEEL"

echo "==> validate"
"$VENV/bin/msgd" --config "$CONFIG" --check

echo "==> restart"
sudo systemctl restart "$SERVICE"

for _ in $(seq 1 50); do
    if curl -fsS http://127.0.0.1:3111/_health >/dev/null; then
        break
    fi
    sleep 0.2
done

curl -fsS http://127.0.0.1:3111/_health
REMOTE

echo "==> public health"
curl -fsS "https://$DOMAIN/_health"
echo
echo "==> updated"
