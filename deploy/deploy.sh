#!/usr/bin/env bash
# Fresh install msg.lmm.best on a clean Arch Linux server.
# Usage: deploy/deploy.sh [ssh-host]
set -euo pipefail

HOST="${1:-archczy}"
DOMAIN="msg.lmm.best"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="/tmp/msg-lmm-best-install.$$"

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
sudo pacman -S --needed --noconfirm python uv nginx certbot curl valkey git openssh
sudo systemctl enable --now valkey.service

/usr/bin/python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 14))' || {
    echo "error: fresh install requires Python 3.14+" >&2
    exit 1
}

echo "==> service account"
sudo install -d -m 0755 /var/empty /var/empty/msg-lmm-best
if ! id -u msg >/dev/null 2>&1; then
    sudo useradd --system --user-group --no-create-home \
        --home-dir /var/empty/msg-lmm-best --shell /bin/sh msg
fi
sudo install -d -o msg -g msg -m 0750 /var/lib/msg-lmm-best

echo "==> application"
sudo install -d -m 0755 /opt/msg-lmm-best /etc/msg-lmm-best /var/lib/letsencrypt
sudo uv venv --quiet --python /usr/bin/python3 "$VENV"
sudo UV_NO_CACHE=1 uv pip install --quiet --python "$VENV/bin/python" \
    --compile-bytecode "$STAGE/dist/$WHEEL"
sudo install -m 0644 "$D/etc/msg-lmm-best/msg.conf" /etc/msg-lmm-best/msg.conf
sudo install -d -m 0755 /etc/msg-lmm-best/templates /etc/msg-lmm-best/commerce
sudo install -m 0644 "$D/etc/msg-lmm-best/templates/store.json" /etc/msg-lmm-best/templates/store.json
sudo install -m 0644 "$D/etc/msg-lmm-best/templates/ads.json" /etc/msg-lmm-best/templates/ads.json
sudo install -m 0644 "$D/etc/msg-lmm-best/privacy.md" /etc/msg-lmm-best/privacy.md
sudo install -m 0644 "$D/etc/msg-lmm-best/terms.md" /etc/msg-lmm-best/terms.md

echo "==> root CA"
sudo "$VENV/bin/msgd-cert" init-root
"$VENV/bin/msgd" --config /etc/msg-lmm-best/msg.conf --check
sudo rm -f /usr/local/bin/msgd-admin
sudo ln -sfn "$VENV/bin/msgdctl" /usr/local/bin/msgdctl
sudo ln -sfn "$VENV/bin/msgd-cert" /usr/local/bin/msgd-cert
sudo ln -sfn "$VENV/bin/msg-ssh-auth" /usr/local/bin/msg-ssh-auth
sudo ln -sfn "$VENV/bin/msg-ssh-shell" /usr/local/bin/msg-ssh-shell

echo "==> sshd restricted account"
sudo install -d -m 0755 /etc/ssh/sshd_config.d
sudo install -m 0644 "$D/sshd/msg-lmm-best.conf" \
    /etc/ssh/sshd_config.d/msg-lmm-best.conf
sudo /usr/bin/sshd -t
SSH_EFFECTIVE="$(sudo /usr/bin/sshd -T -C user=msg,host=localhost,addr=127.0.0.1)"
grep -Fx 'authenticationmethods publickey' <<<"$SSH_EFFECTIVE" >/dev/null
grep -Fx 'passwordauthentication no' <<<"$SSH_EFFECTIVE" >/dev/null
grep -Fx 'authorizedkeysfile none' <<<"$SSH_EFFECTIVE" >/dev/null
grep -Fx 'disableforwarding yes' <<<"$SSH_EFFECTIVE" >/dev/null
grep -F 'authorizedkeyscommand /usr/local/bin/msg-ssh-auth' \
    <<<"$SSH_EFFECTIVE" >/dev/null
sudo systemctl reload sshd.service

echo "==> systemd"
sudo install -m 0644 "$D/msg-lmm-best.service" /etc/systemd/system/msg-lmm-best.service
sudo systemctl daemon-reload
sudo systemctl enable --now msg-lmm-best.service

for _ in $(seq 1 50); do
    if curl -fsS http://127.0.0.1:3111/_health >/dev/null; then
        break
    fi
    sleep 0.2
done
curl -fsS http://127.0.0.1:3111/_health

echo "==> seed default /store products"
sudo "$VENV/bin/msg" \
    --api http://127.0.0.1:3111 \
    --key /etc/msg-lmm-best/root-ca.key \
    post store \
    --fields-file "$D/etc/msg-lmm-best/products/membership.json"

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
