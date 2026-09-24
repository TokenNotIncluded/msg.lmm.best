#!/usr/bin/env bash
# Build and deploy msgd. Existing msg.conf is kept unless FORCE_CONFIG=1.
set -euo pipefail

HOST="${1:-archczy}"
DOMAIN="msg.lmm.best"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="/tmp/msg-lmm-best-deploy.$$"

cd "$ROOT"
echo "==> tests"
PYTHONPATH=src python3 -m unittest discover -s tests -q

echo "==> build wheel"
rm -rf dist
uv build --wheel --quiet
WHEEL="$(basename dist/*.whl)"

echo "==> staging on $HOST:$STAGE"
ssh "$HOST" "mkdir -p $STAGE"
tar -C "$ROOT" -cf - "dist/$WHEEL" deploy | ssh "$HOST" "tar -C $STAGE -xf -"

ssh "$HOST" STAGE="$STAGE" WHEEL="$WHEEL" DOMAIN="$DOMAIN" \
    FORCE_CONFIG="${FORCE_CONFIG:-0}" 'bash -s' <<'REMOTE'
set -euo pipefail
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/deploy"
VENV=/opt/msg-lmm-best/venv

if ! command -v uv >/dev/null; then
    sudo pacman -S --needed --noconfirm uv >/dev/null
fi

sudo install -d -m 0755 /opt/msg-lmm-best
sudo UV_NO_CACHE=1 uv venv --quiet --allow-existing --python /usr/bin/python3 "$VENV"
sudo UV_NO_CACHE=1 uv pip install --quiet --python "$VENV/bin/python" \
    --reinstall --no-deps --compile-bytecode "$STAGE/dist/$WHEEL"

echo "==> config"
sudo install -d -m 0755 /etc/msg-lmm-best
if [[ "$FORCE_CONFIG" == 1 || ! -e /etc/msg-lmm-best/msg.conf ]]; then
    sudo install -m 0644 "$D/etc/msg-lmm-best/msg.conf" /etc/msg-lmm-best/msg.conf
else
    echo "    kept existing msg.conf"
fi
"$VENV/bin/msgd" --config /etc/msg-lmm-best/msg.conf --check

echo "==> systemd"
sudo install -m 0644 "$D/msg-lmm-best.service" /etc/systemd/system/msg-lmm-best.service
sudo systemctl daemon-reload
sudo systemctl enable msg-lmm-best.service >/dev/null
sudo systemctl restart msg-lmm-best.service
for _ in $(seq 1 50); do
    curl -fsS -o /dev/null http://127.0.0.1:3111/_health && break
    sleep 0.2
done
curl -fsS http://127.0.0.1:3111/_health | head -4

install_vhost() {
    local conf
    conf="$(cat "$D/nginx/$DOMAIN.conf")"
    if [[ "$1" == 1 ]]; then
        conf="$(printf '%s\n' "$conf" | sed 's/^#TLS# \{0,1\}//')"
    fi
    sudo install -m 0644 "$D/nginx/$DOMAIN.proxy.conf" "/etc/nginx/$DOMAIN.proxy.conf"
    printf '%s\n' "$conf" | sudo tee "/etc/nginx/conf.d/$DOMAIN.conf" >/dev/null
    sudo nginx -t -q
    sudo systemctl reload nginx
}

CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
if sudo test -e "$CERT"; then
    install_vhost 1
else
    install_vhost 0
    sudo certbot certonly --webroot -w /var/lib/letsencrypt -d "$DOMAIN" \
        --key-type ecdsa --non-interactive --agree-tos \
        --register-unsafely-without-email --keep-until-expiring \
        --deploy-hook "systemctl reload nginx"
    install_vhost 1
fi
REMOTE

echo "==> smoke test https://$DOMAIN"
curl -fsS "https://$DOMAIN/_health"
