# High-level network reconnaissance MCP tools

The Security MCP exposes five high-level tools for assessing a newly connected Ethernet or Wi-Fi network. They remain behind Pi's bounded `mcp_search` gate; adding them does not add their schemas to every model prompt.

## Architecture

```text
Pi / model
   |
   | mcp_search(server="security") -> mcp_call
   v
mcp-security (Docker, existing bounded MCP server)
   |\
   | +-- Graphviz dot -> shared /workspace maps
   |
   | Unix socket when host observation is needed
   v
security-host-recon-helper (systemd on the laptop)
   |
   +-- ip / ethtool
   +-- nmap
   +-- iw / nmcli
   +-- avahi-browse
   +-- airodump-ng (passive; pre-existing monitor interface only)
   +-- tshark (optional passive L2 observation)
```

The host helper is deliberately **not** another network-listening MCP endpoint. It accepts only the four host-observation schemas (`get_host_interface_info`, `perform_network_discovery`, `analyze_network_topology`, and `analyze_wireless_environment`) over `/run/mcp-security-host/recon.sock`; there is no arbitrary shell endpoint. `generate_graphical_network_map` always runs inside `mcp-security` so map files land in the normal shared MCP workspace. The Docker MCP mounts the helper socket read-only. If the helper is absent, the observation tools fall back to the container network namespace and return an explicit scope warning. The installer copies the helper and its required modules into root-owned `/opt/mcp-security-host` before starting the privileged service, so the service does not execute JavaScript directly from the user-writable Git checkout.

## Exact MCP tool definitions

These are the JSON definitions returned by `tools/list` for the five tools (before the server adds the standard MCP annotations):

```json
[
  {
    "name": "get_host_interface_info",
    "description": "Host network-state inventory for a laptop connected to a new Ethernet or Wi-Fi network. Reports active/default interfaces, wired vs wireless type, IPv4/IPv6 addresses, routes/default gateway, link speed, Wi-Fi association metadata when available, and a bounded external-connectivity check. Full host visibility is provided by the optional security host-recon helper; otherwise visibility is limited to the mcp-security container namespace.",
    "inputSchema": {
      "type": "object",
      "description": "Host network-state inventory for a laptop connected to a new Ethernet or Wi-Fi network. Reports active/default interfaces, wired vs wireless type, IPv4/IPv6 addresses, routes/default gateway, link speed, Wi-Fi association metadata when available, and a bounded external-connectivity check. Full host visibility is provided by the optional security host-recon helper; otherwise visibility is limited to the mcp-security container namespace.",
      "properties": {
        "interface": {
          "type": "string",
          "description": "Host network interface name such as eth0, enp1s0, wlan0, or wlp2s0.",
          "maxLength": 64
        },
        "internet_check": {
          "type": "boolean",
          "description": "Check default-route, DNS-resolution, and one ICMP reachability probe to a fixed public resolver; default true."
        }
      },
      "required": [],
      "additionalProperties": false
    }
  },
  {
    "name": "perform_network_discovery",
    "description": "Comprehensive authorized local-network discovery. Discovers live hosts, resolves names from Nmap/reverse DNS/mDNS/locally visible DHCP leases, fingerprints operating systems, scans ports/services, and identifies SMB/NFS shares and common DLNA/Plex/Jellyfin/Emby media services. CIDRs may be supplied or inferred from the selected host interface. Large inferred networks are clamped to the local /24 unless explicitly supplied.",
    "inputSchema": {
      "type": "object",
      "description": "Comprehensive authorized local-network discovery. Discovers live hosts, resolves names from Nmap/reverse DNS/mDNS/locally visible DHCP leases, fingerprints operating systems, scans ports/services, and identifies SMB/NFS shares and common DLNA/Plex/Jellyfin/Emby media services. CIDRs may be supplied or inferred from the selected host interface. Large inferred networks are clamped to the local /24 unless explicitly supplied.",
      "properties": {
        "cidrs": {
          "type": "array",
          "description": "One to four authorized IPv4 CIDRs. Omit to infer directly connected networks from the active interface.",
          "items": {
            "type": "string",
            "description": "Authorized private/allowlisted IPv4 CIDR such as 192.168.1.0/24.",
            "maxLength": 64
          },
          "maxItems": 4
        },
        "interface": {
          "type": "string",
          "description": "Host network interface name such as eth0, enp1s0, wlan0, or wlp2s0.",
          "maxLength": 64
        },
        "max_hosts": {
          "type": "integer",
          "description": "Maximum live hosts to enrich; default 64, maximum 128.",
          "minimum": 1,
          "maximum": 128
        },
        "port_profile": {
          "type": "string",
          "description": "Port coverage: quick=top 100, standard=top 1000 plus common share/media ports, full=all TCP ports. Full is limited to at most 16 hosts.",
          "enum": [
            "quick",
            "standard",
            "full"
          ]
        },
        "os_detection": {
          "type": "boolean",
          "description": "Attempt Nmap OS fingerprinting; default true. Requires raw-packet privileges."
        },
        "resolve_names": {
          "type": "boolean",
          "description": "Resolve names using DHCP lease files, reverse DNS, and mDNS where available; default true."
        },
        "include_shares": {
          "type": "boolean",
          "description": "Enumerate SMB/NFS shares read-only when their services are detected; default true."
        },
        "include_media": {
          "type": "boolean",
          "description": "Probe common UPnP/DLNA/Plex/Jellyfin/Emby ports and metadata; default true."
        },
        "timeout_seconds": {
          "type": "integer",
          "description": "Overall per-phase scan budget; default 180, maximum 600.",
          "minimum": 30,
          "maximum": 600
        }
      },
      "required": [],
      "additionalProperties": false
    }
  },
  {
    "name": "analyze_network_topology",
    "description": "Analyze local network structure and behavior. Reports connected subnets, routes, VLAN interfaces/IDs, gateways, mDNS service visibility and possible reflection across subnets. Optionally tests specified same-subnet peers for possible Wi-Fi client isolation using bounded ICMP/ARP discovery; it does not spoof or poison traffic.",
    "inputSchema": {
      "type": "object",
      "description": "Analyze local network structure and behavior. Reports connected subnets, routes, VLAN interfaces/IDs, gateways, mDNS service visibility and possible reflection across subnets. Optionally tests specified same-subnet peers for possible Wi-Fi client isolation using bounded ICMP/ARP discovery; it does not spoof or poison traffic.",
      "properties": {
        "interface": {
          "type": "string",
          "description": "Host network interface name such as eth0, enp1s0, wlan0, or wlp2s0.",
          "maxLength": 64
        },
        "peer_targets": {
          "type": "array",
          "description": "Known authorized peer IPs expected to be on the same local network. Supplying peers enables the client-isolation test.",
          "items": {
            "type": "string",
            "description": "Authorized peer IPv4 address."
          },
          "maxItems": 16
        },
        "observe_mdns": {
          "type": "boolean",
          "description": "Browse mDNS/DNS-SD services for topology hints; default true."
        },
        "observe_l2": {
          "type": "boolean",
          "description": "Passively observe LLDP/CDP for topology hints; default false and requires SECURITY_ALLOW_PACKET_CAPTURE=true."
        },
        "timeout_seconds": {
          "type": "integer",
          "description": "Observation/probe duration per bounded operation; default 8, maximum 30.",
          "minimum": 3,
          "maximum": 30
        }
      },
      "required": [],
      "additionalProperties": false
    }
  },
  {
    "name": "analyze_wireless_environment",
    "description": "Passive Wi-Fi health/security/congestion analysis using iw and nmcli, with optional airodump-ng collection from an already-existing monitor-mode interface. Reports current association, signal, bitrate/PHY hints, nearby BSSIDs/channels/security, channel congestion/overlap, and visible station data where the driver/interface mode exposes it. Never enables monitor mode, deauthenticates clients, captures credentials, or injects frames.",
    "inputSchema": {
      "type": "object",
      "description": "Passive Wi-Fi health/security/congestion analysis using iw and nmcli, with optional airodump-ng collection from an already-existing monitor-mode interface. Reports current association, signal, bitrate/PHY hints, nearby BSSIDs/channels/security, channel congestion/overlap, and visible station data where the driver/interface mode exposes it. Never enables monitor mode, deauthenticates clients, captures credentials, or injects frames.",
      "properties": {
        "interface": {
          "type": "string",
          "description": "Host network interface name such as eth0, enp1s0, wlan0, or wlp2s0.",
          "maxLength": 64
        },
        "rescan": {
          "type": "boolean",
          "description": "Request a fresh nmcli/iw Wi-Fi scan; default true."
        },
        "use_airodump": {
          "type": "boolean",
          "description": "Also collect passive airodump-ng observations; default false. Requires monitor_interface and SECURITY_ALLOW_PACKET_CAPTURE=true."
        },
        "monitor_interface": {
          "type": "string",
          "description": "Host network interface name such as eth0, enp1s0, wlan0, or wlp2s0.",
          "maxLength": 64
        },
        "duration_seconds": {
          "type": "integer",
          "description": "airodump passive observation duration; default 10, maximum 30.",
          "minimum": 3,
          "maximum": 30
        }
      },
      "required": [],
      "additionalProperties": false
    }
  },
  {
    "name": "generate_graphical_network_map",
    "description": "Generate Graphviz DOT/SVG and optional self-contained HTML from aggregated network-recon JSON. The map distinguishes known wired/wireless links, shows gateway/Internet relationships, link speed when known, and annotates hosts with hostname, OS, open ports, shares, and media services. Prefer direct data. input_path refers only to the mcp-security workspace, never the caller/Pi workspace.",
    "inputSchema": {
      "type": "object",
      "description": "Generate Graphviz DOT/SVG and optional self-contained HTML from aggregated network-recon JSON. The map distinguishes known wired/wireless links, shows gateway/Internet relationships, link speed when known, and annotates hosts with hostname, OS, open ports, shares, and media services. Prefer direct data. input_path refers only to the mcp-security workspace, never the caller/Pi workspace.",
      "properties": {
        "data": {
          "type": "object",
          "description": "Preferred input: aggregated object containing exact outputs from get_host_interface_info, perform_network_discovery, analyze_network_topology and/or analyze_wireless_environment.",
          "additionalProperties": true
        },
        "input_path": {
          "type": "string",
          "description": "Optional mcp-security-workspace-relative JSON file containing aggregated network data. This is not a Pi/native caller workspace path; callers such as Pi should prefer data."
        },
        "output_base": {
          "type": "string",
          "description": "Workspace-relative output basename without extension; default .security-results/network-map.",
          "maxLength": 240
        },
        "format": {
          "type": "string",
          "description": "Map output format.",
          "enum": [
            "svg",
            "html",
            "both"
          ]
        },
        "title": {
          "type": "string",
          "description": "Optional map title; maximum 120 characters.",
          "maxLength": 120
        }
      },
      "required": [],
      "additionalProperties": false
    }
  }
]
```

## Behavior

### `get_host_interface_info`

Uses `ip -j addr`, `ip -j route`, `iw`, and `ethtool`. It determines the selected/default interface, Ethernet versus Wi-Fi, local IPv4/IPv6 addresses, default gateway, link metadata, and an optional bounded connectivity check using one ICMP probe to `1.1.1.1` plus normal resolver lookup of `example.com`.

### `perform_network_discovery`

The tool first performs bounded Nmap host discovery against explicit private/allowlisted CIDRs or CIDRs inferred from the selected interface. Inferred networks larger than `/20` are clamped to the local `/24`; explicit CIDRs must be `/20` through `/32`. At most 128 discovered hosts are enriched, and `full` TCP scanning is restricted to at most 16 hosts.

It then performs service/version detection and optional Nmap OS fingerprinting, probes common share/media ports, performs read-only SMB/NFS share enumeration, and probes UPnP where requested. Name enrichment uses locally visible dnsmasq leases under the mounted host root, `avahi-resolve-address`, the local gateway's DNS resolver, and `getent`, in that order. Results distinguish observed facts from missing evidence rather than inferring an operating system from a service banner alone.

### `analyze_network_topology`

Uses host routes/address/link metadata to report subnets, gateways and VLAN IDs. `avahi-browse` provides mDNS/DNS-SD visibility; an address advertised through mDNS but outside the selected interface subnet is reported only as **possible reflector/repeater evidence**, not proof.

Client-isolation testing is opt-in through `peer_targets`. The tool tests only supplied authorized same-subnet peers and compares their ICMP/ARP/Nmap reachability with gateway reachability. If the gateway responds while all known-live peers do not, the result is `possible_client_isolation_or_peer_filtering`; it does not claim certainty from one station.

Optional LLDP/CDP observation is passive and requires `SECURITY_ALLOW_PACKET_CAPTURE=true`.

### `analyze_wireless_environment`

Uses `iw` and `nmcli` for the normal path: current association, BSSID/SSID, signal, bitrates, channel/frequency, PHY hints (`802.11n/ac/ax/be` when exposed), nearby BSSIDs, security mode and channel congestion/overlap. `iw station dump` is included where the current interface mode/driver exposes station data.

`airodump-ng` is optional. The tool **never** creates monitor mode, changes an interface type, injects frames, sends deauthentication frames, or captures credentials. When `use_airodump=true`, the caller must supply an already-existing `monitor_interface`, and packet capture must be enabled.

### `generate_graphical_network_map`

When Pi is the caller, do not create a native Pi workspace `network_data.json` and pass it as `input_path`; the two containers do not share that path. The Pi bounded gate automatically aggregates successful host/discovery/topology/wireless results and injects them into `data`. The server also prefers a non-empty `data` object over `input_path` when both are present.


Accepts aggregated JSON directly or from a workspace JSON file. It writes Graphviz `.dot`, SVG, and optionally a self-contained HTML rendering in the normal MCP workspace. The rendered topology uses Internet/gateway/AP infrastructure nodes, dashed subnet/VLAN group boxes, and per-client annotations for IP/hostname, MAC, OS evidence, open ports, shares and media services. Known Wi-Fi links are dashed; known wired links are solid; link rate is shown when available. The result is a logical topology unless LLDP/CDP, router/AP station data, or other evidence establishes physical links.

## Host dependencies

### Arch Linux host

```bash
sudo pacman -S --needed nodejs nmap iproute2 iw networkmanager aircrack-ng avahi ethtool iputils glibc bind wireshark-cli smbclient nfs-utils
```

NetworkManager must be running for `nmcli`. `avahi-daemon` should be running for full Avahi resolution/browse behavior:

```bash
sudo systemctl enable --now NetworkManager.service avahi-daemon.service
```

### Debian security image

The Dockerfile installs the corresponding packages: `nmap`, `iproute2`, `iw`, `network-manager`, `aircrack-ng`, `avahi-utils`, `graphviz`, `ethtool`, `iputils-ping`, `dnsutils`, `tshark`, `smbclient`, and `nfs-common`.

## Permissions

The recommended host helper runs as root but is systemd-hardened and bounds the process to `CAP_NET_RAW` and `CAP_NET_ADMIN`. Those capabilities are required for reliable Nmap SYN/OS fingerprinting and low-level wireless/network operations. Ordinary route/address inspection does not require those capabilities. Graphviz generation is deliberately not delegated to the privileged helper and runs inside `mcp-security`.

`SECURITY_ALLOW_PACKET_CAPTURE=false` remains the default. Set it to true only when passive packet observation or the optional airodump path is required. Airodump additionally requires a monitor-mode interface that you create/manage outside the MCP tool.

Active target operations remain constrained by `SECURITY_TARGET_ALLOWLIST`; public targets remain disabled by default.

## Install the host helper

From the gateway repository:

```bash
cd ~/Projects/mcp-gateway
./scripts/install-security-host-recon-helper.sh --install-deps
```

The installer writes and enables `mcp-security-host-recon.service`. Its writable state lives under root-owned `/var/lib/mcp-security-host`, not inside the user Git checkout, so `ProtectHome=true` remains enabled. Verify it with:

```bash
sudo curl --unix-socket /run/mcp-security-host/recon.sock http://localhost/health
```

If an earlier helper revision failed with `EACCES` while trying to create `~/Projects/mcp-gateway/data/workspace`, rerunning the installer replaces that unit. The helper now uses `/var/lib/mcp-security-host/workspace` under systemd `StateDirectory=` and does not need write access to your home directory.

Then rebuild/recreate `mcp-security` so the Unix-socket mount and new binaries are present:

```bash
docker compose build mcp-security
docker compose up -d --no-deps --force-recreate mcp-security
node scripts/validate-catalog.mjs
node --test tests/security.test.mjs
```

## Example agent workflow

```text
get_host_interface_info
  -> perform_network_discovery
  -> analyze_network_topology
  -> analyze_wireless_environment   (when Wi-Fi is active)
  -> generate_graphical_network_map
```

For a map, aggregate the prior results into an object such as:

```json
{
  "interface_info": { "...": "get_host_interface_info result" },
  "discovery": { "...": "perform_network_discovery result" },
  "topology": { "...": "analyze_network_topology result" },
  "wireless": { "...": "analyze_wireless_environment result" }
}
```

### Host helper concurrency

The host helper serializes privileged reconnaissance operations through a bounded queue instead of returning an immediate `busy` error when another scan is active. The default queue depth is 8 (`SECURITY_HOST_RECON_MAX_QUEUE`). `GET /health` and `GET /status` over the Unix socket report the active tool and queued request count. This keeps long-running Nmap discovery from causing unrelated follow-up calls to fail spuriously.


### Physical interface provenance

Physical-interface filtering now requires Linux sysfs device backing (`/sys/class/net/<iface>/device`) for non-Wi-Fi Ethernet interfaces; `iw` remains authoritative for Wi-Fi. This deliberately fails closed on ambiguous software links so automatic reconnaissance does not scan virtual/container networks.
