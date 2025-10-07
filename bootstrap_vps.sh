#!/usr/bin/env bash
set -euo pipefail

# Bootstrap a fresh Ubuntu VPS over SSH from your local machine.
# Creates a sudo user with your SSH key, hardens SSH, enables UFW, sets unattended upgrades,
# optionally changes the SSH port, optionally installs Node LTS, Nginx, and Certbot.

# Usage:
#   ./bootstrap_vps.sh \
#     --host 1.2.3.4 \
#     --new-user adam \
#     --pubkey ~/.ssh/id_ed25519.pub \
#     [--ssh-port 22] \
#     [--new-ssh-port 2022] \
#     [--allow-ssh-from 203.0.113.10] \
#     [--install-node] \
#     [--setup-nginx] \
#     [--domain example.com]
#
# Notes:
# - First connection is as root on the current --ssh-port. Root login will be disabled at the end.
# - If you set --new-ssh-port, the firewall and sshd are updated in-place; the existing session survives the restart.
# - If you set --allow-ssh-from, SSH is restricted to that IP in UFW.

HOST=""
SSH_PORT=22
NEW_USER=""
PUBKEY_PATH=""
NEW_SSH_PORT=""
ALLOW_SSH_FROM=""
INSTALL_NODE=false
SETUP_NGINX=false
DOMAIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --new-user) NEW_USER="$2"; shift 2 ;;
    --pubkey) PUBKEY_PATH="$2"; shift 2 ;;
    --new-ssh-port) NEW_SSH_PORT="$2"; shift 2 ;;
    --allow-ssh-from) ALLOW_SSH_FROM="$2"; shift 2 ;;
    --install-node) INSTALL_NODE=true; shift ;;
    --setup-nginx) SETUP_NGINX=true; shift ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$HOST" || -z "$NEW_USER" || -z "$PUBKEY_PATH" ]]; then
  echo "Required: --host, --new-user, --pubkey" >&2
  exit 1
fi
if [[ ! -r "$PUBKEY_PATH" ]]; then
  echo "Public key not readable: $PUBKEY_PATH" >&2
  exit 1
fi

PUBKEY="$(cat "$PUBKEY_PATH")"

ssh_root() {
  ssh -o StrictHostKeyChecking=accept-new -p "$SSH_PORT" root@"$HOST" "$@"
}

scp_root() {
  scp -P "$SSH_PORT" "$@"
}

echo "[*] Connecting to $HOST on port $SSH_PORT as root"
# Update and base tools
ssh_root bash -s <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y
apt-get install -y sudo ufw curl ca-certificates gnupg lsb-release software-properties-common vim nano
# Some monitoring tools (best-effort)
apt-get install -y htop iotop net-tools || true
EOF

# Create sudo user and authorize SSH key
echo "[*] Creating user $NEW_USER and installing SSH key"
ssh_root bash -s <<EOF
set -euo pipefail
id -u "$NEW_USER" >/dev/null 2>&1 || adduser --disabled-password --gecos "" "$NEW_USER"
usermod -aG sudo "$NEW_USER"

install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" /home/"$NEW_USER"/.ssh
AUTHORIZED=/home/"$NEW_USER"/.ssh/authorized_keys
touch "\$AUTHORIZED"
chown "$NEW_USER:$NEW_USER" "\$AUTHORIZED"
chmod 600 "\$AUTHORIZED"

# Add key if not already present
grep -qxF "$PUBKEY" "\$AUTHORIZED" || echo "$PUBKEY" >> "\$AUTHORIZED"
EOF

# Configure UFW
echo "[*] Configuring UFW"
ssh_root bash -s <<EOF
set -euo pipefail
ufw --force reset || true
ufw default deny incoming
ufw default allow outgoing
# Allow SSH on current port
ufw allow ${SSH_PORT}/tcp
# Optionally restrict to IP
if [[ -n "$ALLOW_SSH_FROM" ]]; then
  ufw delete allow ${SSH_PORT}/tcp >/dev/null 2>&1 || true
  ufw allow from "$ALLOW_SSH_FROM" to any port ${SSH_PORT} proto tcp
fi
# Allow web
ufw allow 80/tcp
ufw allow 443/tcp
yes | ufw enable
ufw status verbose
EOF

# Harden SSH: disable password auth and root login, optionally change port
echo "[*] Hardening SSH"
SSH_EDIT_SCRIPT=$(cat <<'EOS'
set -euo pipefail
SSHD="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
mkdir -p "$DROPIN_DIR"

# Create a managed drop-in to avoid conflicting with cloud-init defaults
CONF="$DROPIN_DIR/99-bootstrap.conf"
touch "$CONF"
chmod 644 "$CONF"

ensure_kv () {
  local key="$1"; local val="$2"
  if grep -qiE "^\s*${key}\s+" "$CONF"; then
    sed -i -E "s|^\s*(${key})\s+.*|\1 ${val}|I" "$CONF"
  else
    echo "${key} ${val}" >> "$CONF"
  fi
}

# Disable password auth and root login
ensure_kv "PasswordAuthentication" "no"
ensure_kv "PubkeyAuthentication" "yes"
ensure_kv "PermitRootLogin" "no"
EOS
)

if [[ -n "$NEW_SSH_PORT" ]]; then
  SSH_EDIT_SCRIPT+=$'\n''ensure_kv "Port" "'"$NEW_SSH_PORT"'"'
fi
SSH_EDIT_SCRIPT+=$'\n''systemctl reload ssh || systemctl restart ssh'

ssh_root bash -s <<EOF
$SSH_EDIT_SCRIPT
EOF

# If we changed the SSH port, update UFW accordingly and adjust our local SSH_PORT for any later steps
if [[ -n "$NEW_SSH_PORT" && "$NEW_SSH_PORT" != "$SSH_PORT" ]]; then
  echo "[*] Updating UFW for new SSH port $NEW_SSH_PORT"
  ssh_root bash -s <<EOF
set -euo pipefail
# Allow new port
if [[ -n "$ALLOW_SSH_FROM" ]]; then
  ufw allow from "$ALLOW_SSH_FROM" to any port ${NEW_SSH_PORT} proto tcp
else
  ufw allow ${NEW_SSH_PORT}/tcp
fi
# Remove old rule
if ufw status | grep -q " ${SSH_PORT}/tcp"; then ufw delete allow ${SSH_PORT}/tcp || true; fi
ufw status verbose
EOF
  SSH_PORT="$NEW_SSH_PORT"
fi

# Unattended upgrades
echo "[*] Enabling unattended upgrades"
ssh_root bash -s <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get install -y unattended-upgrades apt-listchanges
# Enable periodic updates and unattended upgrades
cat >/etc/apt/apt.conf.d/20auto-upgrades <<CFG
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CFG

# Basic hardening of unattended-upgrades config
# Keep vendor defaults for origins. Enable auto reboot at 02:00
if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
  sed -i 's|^//\s*\("${distro_id}:\${distro_codename}-security";\)|\1|' /etc/apt/apt.conf.d/50unattended-upgrades || true
  if ! grep -q 'Automatic-Reboot' /etc/apt/apt.conf.d/50unattended-upgrades; then
    printf '\nUnattended-Upgrade::Automatic-Reboot "true";\nUnattended-Upgrade::Automatic-Reboot-Time "02:00";\n' >> /etc/apt/apt.conf.d/50unattended-upgrades
  fi
fi
systemctl restart unattended-upgrades || true
systemctl is-active --quiet unattended-upgrades && echo "unattended-upgrades active"
EOF

# Optional Node LTS + PM2
if $INSTALL_NODE; then
  echo "[*] Installing Node LTS and PM2"
  ssh_root bash -s <<EOF
set -euo pipefail
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt-get install -y nodejs
npm -g install pm2
pm2 --version >/dev/null 2>&1 && echo "PM2 installed"
EOF
fi

# Optional Nginx + Certbot
if $SETUP_NGINX; then
  echo "[*] Installing Nginx"
  ssh_root bash -s <<'EOF'
set -euo pipefail
apt-get install -y nginx
systemctl enable --now nginx
nginx -t
EOF

  if [[ -n "$DOMAIN" ]]; then
    echo "[*] Configuring Nginx for $DOMAIN and obtaining TLS with Certbot"
    ssh_root bash -s <<EOF
set -euo pipefail
SITE=/etc/nginx/sites-available/${DOMAIN}
cat > "\$SITE" <<NGINX
server {
    listen 80;
    server_name ${DOMAIN};
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
NGINX
ln -sf "\$SITE" /etc/nginx/sites-enabled/${DOMAIN}
nginx -t && systemctl reload nginx
apt-get install -y certbot python3-certbot-nginx
certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos -m admin@${DOMAIN} || true
certbot renew --dry-run || true
EOF
  fi
fi

# Final touches: show status and lock root login via password already handled
echo "[*] Final verification"
ssh_root bash -s <<'EOF'
set -euo pipefail
echo "Users:"
getent passwd | awk -F: '$3>=1000 && $1!="nobody"{print $1}'
echo
echo "SSH config drop-ins:"
ls -l /etc/ssh/sshd_config.d || true
echo
echo "UFW:"
ufw status verbose || true
echo
echo "unattended-upgrades:"
systemctl status --no-pager unattended-upgrades | sed -n '1,15p' || true
EOF

echo
echo "[*] Done."
echo "Next:"
echo "  - Test login as: ssh -p $SSH_PORT $NEW_USER@$HOST"
echo "  - Root SSH login is disabled. Password authentication is disabled."
