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
    deploy/msg-lmm-best-index.service \
    deploy/msg-lmm-best-index.timer \
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

echo "==> validate"
"$VENV/bin/msgd" --config "$CONFIG" --check
sudo rm -f /usr/local/bin/msgd-admin
sudo ln -sfn "$VENV/bin/msgdctl" /usr/local/bin/msgdctl
sudo ln -sfn "$VENV/bin/msgd-cert" /usr/local/bin/msgd-cert

echo "==> index timer"
sudo install -m 0644 "$D/msg-lmm-best-index.service" \
    /etc/systemd/system/msg-lmm-best-index.service
sudo install -m 0644 "$D/msg-lmm-best-index.timer" \
    /etc/systemd/system/msg-lmm-best-index.timer
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

sudo systemctl enable --now msg-lmm-best-index.timer
sudo systemctl start msg-lmm-best-index.service

echo "==> nginx upload limit"
sudo install -m 0644 "$D/nginx/msg.lmm.best.proxy.conf" \
    /etc/nginx/msg.lmm.best.proxy.conf
sudo nginx -t
sudo systemctl reload nginx
REMOTE

echo "==> public health"
curl -fsS "https://$DOMAIN/_health"
echo
echo "==> updated"
