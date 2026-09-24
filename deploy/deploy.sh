#!/usr/bin/env bash
# Fresh install msg.lmm.best on a clean Arch Linux server.
# Usage: deploy/deploy.sh [ssh-host]
set -euo pipefail

HOST="${1:-archczy}"
DOMAIN="msg.lmm.best"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="/tmp/msg-lmm-best-install.$$"

cd "$ROOT"

command -v uv >/dev/null || {
    echo "error: uv is required on the local machine" >&2
    exit 1
}

command -v ssh >/dev/null || {
    echo "error: ssh is required on the local machine" >&2
    exit 1
}

echo "==> test"
PYTHONPATH=src python3 -m unittest discover -s tests -q

echo "==> build"
rm -rf dist
uv build --wheel --quiet
WHEEL="$(basename dist/*.whl)"

echo "==> upload"
ssh "$HOST" "rm -rf '$STAGE' && mkdir -p '$STAGE'"
tar -C "$ROOT" -cf - "dist/$WHEEL" deploy | ssh "$HOST" "tar -C '$STAGE' -xf -"

echo "==> install on $HOST"
ssh "$HOST" STAGE="$STAGE" WHEEL="$WHEEL" DOMAIN="$DOMAIN" 'bash -s' <<'REMOTE'
set -euo pipefail
trap 'rm -rf "$STAGE"' EXIT

D="$STAGE/deploy"
VENV=/opt/msg-lmm-best/venv
DB=/var/lib/msg-lmm-best/msg.db

if sudo test -e "$DB"; then
    echo "error: $DB already exists; this script is for fresh installs only" >&2
    exit 1
fi

echo "==> packages"
sudo pacman -S --needed --noconfirm python uv nginx certbot curl

echo "==> application"
sudo install -d -m 0755 /opt/msg-lmm-best /etc/msg-lmm-best /var/lib/letsencrypt
sudo uv venv --quiet --python /usr/bin/python3 "$VENV"
sudo UV_NO_CACHE=1 uv pip install --quiet --python "$VENV/bin/python" \
    --no-deps --compile-bytecode "$STAGE/dist/$WHEEL"
sudo install -m 0644 "$D/etc/msg-lmm-best/msg.conf" /etc/msg-lmm-best/msg.conf
"$VENV/bin/msgd" --config /etc/msg-lmm-best/msg.conf --check

echo "==> systemd"
sudo install -m 0644 "$D/msg-lmm-best.service" /etc/systemd/system/msg-lmm-best.service
sudo install -m 0644 "$D/msg-lmm-best-index.service" /etc/systemd/system/msg-lmm-best-index.service
sudo install -m 0644 "$D/msg-lmm-best-index.timer" /etc/systemd/system/msg-lmm-best-index.timer
sudo systemctl daemon-reload
sudo systemctl enable --now msg-lmm-best.service

for _ in $(seq 1 50); do
    if curl -fsS http://127.0.0.1:3111/_health >/dev/null; then
        break
    fi
    sleep 0.2
done
curl -fsS http://127.0.0.1:3111/_health

echo "==> automatic index"
sudo systemctl enable --now msg-lmm-best-index.timer
sudo systemctl start msg-lmm-best-index.service

echo "==> nginx http"
sudo install -d -m 0755 /etc/nginx/conf.d
sudo install -m 0644 "$D/nginx/nginx.conf" /etc/nginx/nginx.conf
sudo install -m 0644 "$D/nginx/$DOMAIN.proxy.conf" "/etc/nginx/$DOMAIN.proxy.conf"
sudo install -m 0644 "$D/nginx/$DOMAIN.conf" "/etc/nginx/conf.d/$DOMAIN.conf"
sudo nginx -t
sudo systemctl enable --now nginx

echo "==> tls"
sudo certbot certonly --webroot -w /var/lib/letsencrypt -d "$DOMAIN" \
    --key-type ecdsa --non-interactive --agree-tos \
    --register-unsafely-without-email --keep-until-expiring \
    --deploy-hook "systemctl reload nginx"

sed 's/^#TLS# \{0,1\}//' "$D/nginx/$DOMAIN.conf" \
    | sudo tee "/etc/nginx/conf.d/$DOMAIN.conf" >/dev/null
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl enable --now certbot-renew.timer

echo "==> installed"
curl -fsS "https://$DOMAIN/_health"
REMOTE

echo "==> done"
curl -fsS "https://$DOMAIN/_health"
