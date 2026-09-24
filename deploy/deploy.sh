#!/usr/bin/env bash
# Deploy msgd to a host over SSH. Idempotent: safe to re-run for every release.
#
#   deploy/deploy.sh [ssh-host]          # default host: archczy
#   FORCE_CONFIG=1 deploy/deploy.sh      # also overwrite /etc/msg-lmm-best/*
#
# Layout on the host:
#   /opt/msg-lmm-best/server/     code (root-owned, read-only to the service)
#   /etc/msg-lmm-best/msg.conf    config -- only installed if absent
#   /etc/msg-lmm-best/rules.md    house rules -- only installed if absent
#   /var/lib/msg-lmm-best/        SQLite db + hosted files (systemd StateDirectory)
set -euo pipefail

HOST="${1:-archczy}"
DOMAIN="msg.lmm.best"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="/tmp/msg-lmm-best-deploy.$$"

echo "==> tests"
python3 -m unittest discover -s "$ROOT/tests" >/dev/null 2>&1 \
    || { python3 -m unittest discover -s "$ROOT/tests"; exit 1; }

echo "==> staging on $HOST:$STAGE"
ssh "$HOST" "mkdir -p $STAGE"
tar -C "$ROOT" -cf - server/*.py deploy | ssh "$HOST" "tar -C $STAGE -xf -"

ssh "$HOST" STAGE="$STAGE" DOMAIN="$DOMAIN" FORCE_CONFIG="${FORCE_CONFIG:-0}" 'bash -s' <<'REMOTE'
set -euo pipefail
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/deploy"

echo "==> code -> /opt/msg-lmm-best/server"
sudo install -d -m 0755 /opt/msg-lmm-best/server
sudo install -m 0644 "$STAGE"/server/*.py /opt/msg-lmm-best/server/

echo "==> config -> /etc/msg-lmm-best"
sudo install -d -m 0755 /etc/msg-lmm-best
for f in msg.conf rules.md; do
    if [[ "$FORCE_CONFIG" == 1 || ! -e /etc/msg-lmm-best/$f ]]; then
        sudo install -m 0644 "$D/etc/msg-lmm-best/$f" /etc/msg-lmm-best/$f
        echo "    installed $f"
    else
        echo "    kept existing $f (FORCE_CONFIG=1 to overwrite)"
    fi
done
python3 /opt/msg-lmm-best/server/msgsrv.py --config /etc/msg-lmm-best/msg.conf --check

echo "==> systemd unit"
sudo install -m 0644 "$D/msg-lmm-best.service" /etc/systemd/system/msg-lmm-best.service
sudo systemctl daemon-reload
sudo systemctl enable msg-lmm-best.service >/dev/null
sudo systemctl restart msg-lmm-best.service
for _ in $(seq 1 50); do
    curl -fsS -o /dev/null http://127.0.0.1:3111/_health && break
    sleep 0.2
done
curl -fsS http://127.0.0.1:3111/_health | head -1

install_vhost() {
    # $1 = 1 to enable the TLS server block.
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
    echo "==> nginx (http + https)"
    install_vhost 1
else
    echo "==> nginx (http only, to answer the ACME challenge)"
    install_vhost 0
    echo "==> certificate for $DOMAIN"
    sudo certbot certonly --webroot -w /var/lib/letsencrypt -d "$DOMAIN" \
        --key-type ecdsa --non-interactive --agree-tos \
        --register-unsafely-without-email --keep-until-expiring \
        --deploy-hook "systemctl reload nginx"
    echo "==> nginx (http + https)"
    install_vhost 1
fi

echo "==> done"
REMOTE

echo "==> smoke test https://$DOMAIN"
curl -fsS "https://$DOMAIN/_health" | head -3
