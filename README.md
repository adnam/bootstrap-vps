# VPS Bootstrap Script

This script automates the initial setup and security hardening of a new Ubuntu VPS over SSH.  
It implements the core steps from [VPS Setup and Security Checklist](https://bhargav.dev/blog/VPS_Setup_and_Security_Checklist_A_Complete_Self_Hosting_Guide).

---

## Features

- Creates a new sudo user and installs your SSH key  
- Disables root login and password authentication  
- Enables and configures UFW (firewall)  
- Configures automatic security updates (`unattended-upgrades`)  
- Optional SSH port change and IP restriction  
- Optional Node.js LTS + PM2 installation  
- Optional Nginx reverse proxy and HTTPS setup with Certbot  

---

## Requirements

Run this from your **local machine** (not the server):

- macOS or Linux with `bash`, `ssh`, and `scp`
- Root SSH access to a remote Ubuntu 22.04 or 24.04 server
- A valid SSH key pair (e.g. `~/.ssh/id_ed25519.pub`)

---

## Usage

```bash
./bootstrap_vps.sh \
  --host 1.2.3.4 \
  --new-user adam \
  --pubkey ~/.ssh/id_ed25519.pub \
  [--ssh-port 22] \
  [--new-ssh-port 2022] \
  [--allow-ssh-from 203.0.113.10] \
  [--install-node] \
  [--setup-nginx] \
  [--domain example.com]

## Example

```
./bootstrap_vps.sh \
  --host 203.0.113.55 \
  --new-user adam \
  --pubkey ~/.ssh/id_ed25519.pub \
  --new-ssh-port 2222 \
  --allow-ssh-from 82.158.101.24 \
  --install-node \
  --setup-nginx \
  --domain example.com
  ```

  ## Options

| Flag | Description |
|------|--------------|
| `--host` | IP or hostname of the VPS |
| `--ssh-port` | Current SSH port (default `22`) |
| `--new-user` | Name of the new sudo user to create |
| `--pubkey` | Path to your local public key file |
| `--new-ssh-port` | Optional new SSH port to migrate to |
| `--allow-ssh-from` | Restrict SSH access to a single IP |
| `--install-node` | Installs Node.js LTS and PM2 |
| `--setup-nginx` | Installs and configures Nginx |
| `--domain` | Used with Nginx + Certbot for HTTPS |

## What It Does

1. **System Update** – Updates and upgrades all packages using `apt`.
2. **User Setup** – Creates a non-root sudo user and installs your SSH key.
3. **SSH Hardening** – Disables root login, disables password authentication, and optionally changes the SSH port.
4. **Firewall (UFW)** – Enables the firewall, allows only SSH, HTTP, and HTTPS, and optionally restricts SSH access to a specific IP.
5. **Automatic Updates** – Enables `unattended-upgrades` with daily updates and 2:00 AM auto-reboots.
6. **Optional Tools** – Installs Node.js LTS + PM2, Nginx, and Certbot for HTTPS.
