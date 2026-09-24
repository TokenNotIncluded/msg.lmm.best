#!/usr/bin/env bash
# Build msgd with uv and deploy it to a host over SSH. Idempotent: safe to
# re-run for every release.
#
#   deploy/deploy.sh [ssh-host]          # default host: archczy
#   FORCE_CONFIG=1 deploy/deploy.sh      # also overwrite msg.conf and rules.md
#
# Layout on the host:
#   /opt/msg-lmm-best/venv/            uv-managed venv; msgd installed from the wheel
#   /etc/msg-lmm-best/msg.conf         config -- only installed if absent
#   /etc/msg-lmm-best/rules.md         house rules -- only installed if absent
#   /etc/msg-lmm-best/admin.token      operator secret, root 0600, generated once
#   /var/lib/msg-lmm-best/             SQLite db + hosted files (systemd StateDirectory)
#   /var/backups/msg-lmm-best/         a database snapshot per deploy (last 10 kept)
#
# The venv links the system python3. After a minor Python upgrade (3.14 -> 3.15)
# re-run this script to rebuild it.
set -euo pipefail

HOST="${1:-archczy}"
DOMAIN="msg.lmm.best"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="/tmp/msg-lmm-best-deploy.$$"

cd "$ROOT"
echo "==> lint + tests"
uv run --frozen ruff check --quiet .
uv run --frozen pytest -q >/dev/null 2>&1 || { uv run --frozen pytest -q; exit 1; }

echo "==> build wheel"
rm -rf dist
uv build --wheel --quiet
WHEEL="$(basename dist/*.whl)"
echo "    $WHEEL"

echo "==> staging on $HOST:$STAGE"
ssh "$HOST" "mkdir -p $STAGE"
tar -C "$ROOT" -cf - "dist/$WHEEL" deploy | ssh "$HOST" "tar -C $STAGE -xf -"

ssh "$HOST" STAGE="$STAGE" WHEEL="$WHEEL" DOMAIN="$DOMAIN" \
    FORCE_CONFIG="${FORCE_CONFIG:-0}" 'bash -s' <<'REMOTE'
set -euo pipefail
trap 'rm -rf "$STAGE"' EXIT
D="$STAGE/deploy"
VENV=/opt/msg-lmm-best/venv
DB=/var/lib/msg-lmm-best/msg.db

if ! command -v uv >/dev/null; then
    echo "==> installing uv"
    sudo pacman -S --needed --noconfirm uv >/dev/null
fi

if sudo test -e "$DB"; then
    echo "==> snapshot database"
    sudo install -d -m 0700 /var/backups/msg-lmm-best
    snap="/var/backups/msg-lmm-best/msg-$(date -u +%Y%m%dT%H%M%SZ).db"
    sudo python3 -c 'import sqlite3, sys; sqlite3.connect(sys.argv[1]).backup(sqlite3.connect(sys.argv[2]))' \
        "$DB" "$snap"
    sudo find /var/backups/msg-lmm-best -name 'msg-*.db' | sort | head -n -10 | xargs -r sudo rm -f
    echo "    $snap"
fi

echo "==> venv -> $VENV"
sudo install -d -m 0755 /opt/msg-lmm-best
sudo UV_NO_CACHE=1 uv venv --quiet --allow-existing --python /usr/bin/python3 "$VENV"
sudo UV_NO_CACHE=1 uv pip install --quiet --python "$VENV/bin/python" \
    --reinstall --no-deps --compile-bytecode "$STAGE/dist/$WHEEL"
# The pre-uv layout ran loose scripts from here.
sudo rm -rf /opt/msg-lmm-best/server

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
if ! sudo test -s /etc/msg-lmm-best/admin.token; then
    (umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(32))' \
        | sudo tee /etc/msg-lmm-best/admin.token >/dev/null)
    echo "    generated admin.token (read it with: sudo cat /etc/msg-lmm-best/admin.token)"
fi
sudo chown root:root /etc/msg-lmm-best/admin.token
sudo chmod 0600 /etc/msg-lmm-best/admin.token
"$VENV/bin/msgd" --config /etc/msg-lmm-best/msg.conf --check

echo "==> systemd unit"
sudo install -m 0644 "$D/msg-lmm-best.service" /etc/systemd/system/msg-lmm-best.service
sudo systemctl daemon-reload
sudo systemctl enable msg-lmm-best.service >/dev/null
sudo systemctl restart msg-lmm-best.service
for _ in $(seq 1 50); do
    curl -fsS -o /dev/null http://127.0.0.1:3111/_health && break
    sleep 0.2
done
curl -fsS http://127.0.0.1:3111/_health | head -2

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
curl -fsS -o /dev/null -w '    sitemap.xml %{http_code}\n' "https://$DOMAIN/sitemap.xml"
