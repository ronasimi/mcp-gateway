#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi
HOST_STATE_DIR="${SECURITY_HOST_RECON_STATE_DIR:-/var/lib/mcp-security-host}"
WORKSPACE="$HOST_STATE_DIR/workspace"
UNIT=/etc/systemd/system/mcp-security-host-recon.service
INSTALL_DEPS=false
[[ "${1:-}" == "--install-deps" ]] && INSTALL_DEPS=true

bins=(node nmap ip iw nmcli airodump-ng avahi-browse ethtool ping getent dig tshark)
packages=(nodejs nmap iproute2 iw networkmanager aircrack-ng avahi ethtool iputils glibc bind wireshark-cli smbclient nfs-utils)
missing=()
for b in "${bins[@]}"; do command -v "$b" >/dev/null 2>&1 || missing+=("$b"); done
if ((${#missing[@]})); then
  echo "Missing host binaries: ${missing[*]}" >&2
  if $INSTALL_DEPS && command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --needed --noconfirm "${packages[@]}"
  else
    echo "On Arch Linux install them with:" >&2
    echo "  sudo pacman -S --needed ${packages[*]}" >&2
    echo "Then rerun this script, or rerun with --install-deps." >&2
    exit 1
  fi
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<UNIT
[Unit]
Description=MCP Security Host Network Recon Helper
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/mcp-security-host
ExecStart=/usr/bin/node /opt/mcp-security-host/security-host-recon-helper.mjs
Environment="MCP_WORKSPACE=$WORKSPACE"
Environment="SECURITY_HOST_RECON_SOCKET=/run/mcp-security-host/recon.sock"
Environment="SECURITY_HOST_RECON_MAX_QUEUE=${SECURITY_HOST_RECON_MAX_QUEUE:-8}"
Environment="SECURITY_NETWORK_SCOPE=host-network"
Environment="SECURITY_ALLOW_ACTIVE=${SECURITY_ALLOW_ACTIVE:-true}"
Environment="SECURITY_ALLOW_PACKET_CAPTURE=${SECURITY_ALLOW_PACKET_CAPTURE:-false}"
Environment="SECURITY_ALLOW_PUBLIC_TARGETS=${SECURITY_ALLOW_PUBLIC_TARGETS:-false}"
Environment="SECURITY_TARGET_ALLOWLIST=${SECURITY_TARGET_ALLOWLIST:-127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128,fc00::/7,fe80::/10}"
RuntimeDirectory=mcp-security-host
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=restart
StateDirectory=mcp-security-host
StateDirectoryMode=0700
ExecStartPre=/usr/bin/install -d -m 0700 $WORKSPACE
ExecStopPost=/usr/bin/rm -f /run/mcp-security-host/recon.sock
UMask=0077
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$HOST_STATE_DIR /run/mcp-security-host
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
sudo install -d -m 0755 /opt/mcp-security-host
sudo install -m 0755 "$ROOT/scripts/security-host-recon-helper.mjs" /opt/mcp-security-host/security-host-recon-helper.mjs
sudo install -m 0644 "$ROOT/scripts/security-network-recon.mjs" /opt/mcp-security-host/security-network-recon.mjs
sudo install -m 0644 "$ROOT/scripts/security-runtime.mjs" /opt/mcp-security-host/security-runtime.mjs
sudo install -m 0644 "$tmp" "$UNIT"
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-security-host-recon.service
sudo systemctl --no-pager --full status mcp-security-host-recon.service || true
printf '\nHost recon helper socket: /run/mcp-security-host/recon.sock\n'
printf 'Host helper state workspace: %s\n' "$WORKSPACE"
printf 'Health check: sudo curl --unix-socket /run/mcp-security-host/recon.sock http://localhost/health\n'
