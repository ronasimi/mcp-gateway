> Catalog update (2026-10-03): 132 owned tools, concise names and curated descriptions. See [deduplication and search changes](docs/TOOL-DEDUPLICATION.md), [current inventory](docs/TOOL-CATALOG.md), and [run review](docs/RUN-REVIEW-2026-10-03.md).

# Local MCP gateway

A local MCP stack for **stock Pi 1.0 native MCP + built-in `tool_search`**. Pi owns the agent loop and deferred tool loading. The MCP services own capability descriptions, catalog metadata, authorization, input bounds, and execution policy.

## Architecture

Pi reads its normal `mcp.json` through upstream `builtin:mcp`. Each server is configured with `exposure: "deferred"`, so Pi's upstream `tool_search` discovers matching MCP tools and activates exact schemas on demand. This repository contains no Pi agent-loop extension and no custom Pi-side MCP gate.

The owned System, Security, and Google MCP servers publish additional `ai.catalog` metadata plus concise searchable scope/alias text. The metadata distinguishes overlapping tools such as live-host sweep versus comprehensive discovery, container-network diagnostics versus host network state, scalar Gmail counts versus message search, and metadata inspection versus content extraction. Server-side authorization and bounded schemas remain the enforcement boundary.

## Services

| Service | Endpoint | Purpose |
|---|---|---|
| SearXNG MCP | `127.0.0.1:8888/mcp/` | Web search |
| Playwright MCP | `127.0.0.1:8931/mcp` | Browser navigation, snapshots, screenshots |
| Memory MCP | `127.0.0.1:8932/mcp` | Persistent graph memory |
| System Tools MCP | `127.0.0.1:8933/mcp` | Local briefing, Docker, host, network, OpenWrt, image, and document tools |
| Google Workspace MCP | `127.0.0.1:8934/mcp` | Gmail, Calendar, and Drive account tools (optional) |
| Security MCP | `127.0.0.1:8935/mcp` | Authorized security assessment and network reconnaissance |

Containers on the external `ai-local` network use `mcp-searxng:8888`, `mcp-gateway:8931/8932`, and `mcp-system:8933`. When enabled, Google Workspace is `mcp-google:8934`; Security MCP is `mcp-security:8935`.

## Native deferred discovery and catalog metadata

Pi's native `tool_search` searches deferred MCP tool definitions. The MCP catalog therefore optimizes tool names, descriptions, schema descriptions, aliases, and scope distinctions rather than teaching a custom search protocol in the Pi prompt.

Owned MCP tools publish `_meta["ai.catalog"]` with:

- `domain` — system, security, or google
- `aliases` — high-value alternate capability phrasing (empty for tools that need no extra aliases)
- `scope` — the tool's functional boundary
- `overlapGroup` — present on related tools that need clear differentiation
- `preferredFor` — concise selection guidance

For the most commonly confused tools, the same scope/alias information is appended to the normal MCP description so it participates in Pi's built-in lexical/BM25-style tool discovery even when a provider ignores custom `_meta`. Validate the catalog with `node scripts/validate-catalog.mjs`.

## System tools

### London daily briefing

- `local_daily_briefing`

Fetches London, Ontario current weather and a seven-day forecast from Open-Meteo plus the latest CBC London RSS headlines, then returns a preformatted Markdown blockquote card with weather/news icons. It requires no API key and accepts only an optional `headline_count` from 5 to 7. Weather and news are fetched independently, so a failure in one source is shown inline while the other section still renders.

### Docker

Read/diagnostic tools include container listing/inspection/logs/stats, image listing/inspection, network inspection, and volume inspection. Optional tools cover in-container exec, lifecycle actions, container removal, and image removal.

- `docker_list_containers`
- `docker_inspect_container`
- `docker_container_logs`
- `docker_container_stats`
- `docker_list_images`
- `docker_inspect_image`
- `docker_list_networks`
- `docker_inspect_network`
- `docker_list_volumes`
- `docker_inspect_volume`
- `docker_exec`
- `docker_container_action`
- `docker_remove_container`
- `docker_remove_image`

`docker_list_containers` defaults to running containers only (`all=false`) and returns a compact normalized summary rather than raw Docker API objects. `docker_exec` is disabled by default with `DOCKER_ALLOW_EXEC=false`. Lifecycle/removal operations are disabled by default with `DOCKER_ALLOW_WRITE=false`.


### Host

Host tools read from a read-only bind mount of the host root and expose bounded diagnostics rather than a generic host shell.

- `host_snapshot`
- `host_cpu_info`
- `host_memory_info`
- `host_processes`
- `host_process_info`
- `host_disk_usage`
- `host_read_file`

`host_read_file` is restricted to `/etc`, `/proc`, `/sys`, `/var/log`, and `/run` and rejects binary files.

### Network

- `network_dns_lookup`
- `network_ping`
- `network_trace_route`
- `network_http_probe`
- `network_port_check`

System connectivity checks originate in the System container. Laptop/LAN state and discovery belong to Security `get_host_interface_info` and `perform_network_discovery`, through the required host helper. Targeted TCP/service scans use Security `port_scan`. DNS accepts either `type` or `types`, including PTR and CAA.

### OpenWrt

OpenWrt access is SSH-key/config based. The model refers to a configured SSH alias instead of receiving credentials in a tool call.

- `openwrt_targets` — discover configured SSH aliases
- `openwrt_status`
- `openwrt_uci_show`
- `openwrt_uci_get`
- `openwrt_ubus_call`
- `openwrt_logread`
- `openwrt_wifi_status`
- `openwrt_clients`
- `openwrt_package_query`
- `openwrt_service_action`
- `openwrt_uci_set`

Write operations are disabled by default with `OPENWRT_ALLOW_WRITE=false`.

Example `data/ssh/config`:

```sshconfig
Host router-main
    HostName 192.168.1.1
    User root
    IdentityFile /data/ssh/id_ed25519
    StrictHostKeyChecking accept-new

Host router-nas
    HostName 192.168.1.2
    User root
    IdentityFile /data/ssh/id_ed25519
    StrictHostKeyChecking accept-new
```

Place the referenced private key in `data/ssh/` and keep its permissions restrictive.

### Images

Image tools are restricted to `MCP_WORKSPACE_PATH` and use ImageMagick/ExifTool. `image_resize` supports ordinary resize geometry or `mode="thumbnail"` with width/height and an explicit enlargement option.

- `image_list`
- `image_info`
- `image_metadata`
- `image_resize`
- `image_crop`
- `image_convert`
- `image_compare`

### Documents

Document tools are also restricted to `MCP_WORKSPACE_PATH`. PDF extraction/rendering uses Poppler; general conversions use Pandoc with DOCX/PPTX/XLSX fallbacks where practical.

- `document_list`
- `document_info`
- `document_extract_text`
- `document_search_text`
- `document_convert`
- `document_render_pdf_page`

Supported discovery/extraction formats include PDF, DOCX, ODT, RTF, HTML, Markdown, text, CSV, XLSX, PPTX, EPUB, JSON, XML, and YAML.

## Credentials and MCP authorization

There are two separate security layers:

1. **MCP client → MCP server authorization.** For remote/untrusted deployments, MCP HTTP authorization follows OAuth 2.1 resource-server patterns. Protect the MCP endpoint with tokens issued for that MCP resource; do not reuse or pass through Google access tokens as MCP bearer tokens.
2. **MCP server → upstream service credentials.** Google OAuth client credentials and user refresh tokens belong to the server. They must never be prompt text, MCP tool arguments, search keywords, or normal tool results. A browser/out-of-band OAuth flow should deliver the upstream token directly to server-controlled storage.

This repository is optimized for a local trusted `ai-local` network. Google upstream credentials are therefore isolated with Compose secrets plus an encrypted persistent token file. If you later expose an MCP endpoint outside the local host/network, add MCP-standard OAuth protection at the HTTP boundary as a separate layer.

## Google Workspace (Gmail, Calendar, Drive)

Google account tools run in a separate `mcp-google` container with no Docker socket, host-root mount, or OpenWrt SSH keys. OAuth secrets never appear in MCP tool arguments, schemas, or results. The OAuth client JSON is mounted as a Compose secret; the user refresh/access token is stored in `data/google/token.enc.json`, encrypted with AES-256-GCM using a separate key mounted as another secret.

### One-time Google setup

1. In your existing Google Cloud project, enable **Gmail API**, **Google Calendar API**, and **Google Drive API**.
2. Configure the OAuth consent screen. If the app is External + Testing, add your Google account as a test user.
3. Create an **OAuth 2.0 Client ID → Desktop app** and download its JSON to:

```text
secrets/google-oauth-client.json
```

4. Run:

```bash
./scripts/google-auth.sh
```

The script builds the isolated Google MCP image, prints a Google authorization URL, listens only on `127.0.0.1:53682` for the OAuth callback, encrypts the returned token, and starts `mcp-google`.

Default scopes are broad read-only access needed by an agent that can search/read Gmail and Drive plus narrower Calendar scopes:

```text
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/calendar.calendarlist.readonly
https://www.googleapis.com/auth/calendar.events.readonly
https://www.googleapis.com/auth/calendar.freebusy
https://www.googleapis.com/auth/drive.readonly
```

Gmail `gmail.readonly` and Drive `drive.readonly` are Google **restricted scopes**. For a smaller Drive permission surface, use `drive.file`, but it only covers files created/opened/shared with the app rather than arbitrary Drive files. Google recommends requesting the narrowest scopes that satisfy the feature.

If the OAuth consent screen is External and remains in **Testing**, Google refresh tokens for these scopes expire after 7 days. Plan to reauthorize during testing or move the OAuth app to the appropriate production state for persistent use. Verification/security-assessment requirements depend on the scopes, audience, distribution, and how user data is stored/transmitted.

### Account write gates

All account mutations are independently off by default:

```dotenv
GOOGLE_GMAIL_WRITE=false
GOOGLE_CALENDAR_WRITE=false
GOOGLE_DRIVE_WRITE=false
```

Enabling a gate does not grant an OAuth scope. Re-run `./scripts/google-auth.sh` after changing `GOOGLE_SCOPES` to include suitable write access. Typical choices are Gmail `gmail.modify`, Calendar `calendar.events`, and Drive `drive.file` (or broader `drive` only when genuinely required).

Google tools include:

- Gmail: exact unread count, search/read message, read thread, labels, create draft, send draft, modify labels.
- Calendar: list calendars/events, get event, free/busy, create/update/delete event.
- Drive: search, metadata, read text, download/export to the shared MCP workspace, create folder, upload, delete.

`drive_download_file` writes into the same workspace used by the image/document MCP tools, so a Drive PDF/DOCX can be downloaded first and then processed by `document_extract_text`, `document_search_text`, or `document_render_pdf_page` without exposing binary content to the model.

## Install / update

```bash
./scripts/init.sh
```

The initializer:

- creates the external `ai-local` network if required;
- creates persistent SearXNG, Playwright, Memory, workspace, SSH, and Google state directories;
- generates `SEARXNG_SECRET` and a local Google token-encryption key;
- builds the Playwright/Memory and System Tools images;
- starts the core stack;
- builds/starts Google Workspace automatically when `secrets/google-oauth-client.json` exists;
- runs the status checks.

For the standard `~/Projects/pi-docker` layout, install the stock Pi prompt/native MCP configuration and upgrade Pi with:

```bash
./scripts/deploy-stock-pi-1.0.sh ~/Projects/pi-docker
```

The deploy helper validates the MCP catalogs, rebuilds the owned MCP services that publish catalog metadata, copies `pi/APPEND_SYSTEM.md` and `pi/mcp.json.example` into the Pi Docker repo, then invokes Pi's stock 1.0 upgrade script. Existing Pi/Web UI bind mounts stay in place.

## Workspace

By default image/document tools see only:

```text
./data/workspace
```

Set a host directory in `.env` when Pi should work on real project files:

```dotenv
MCP_WORKSPACE_PATH=/home/you/Projects
```

The mount is read/write because image/document conversion tools create outputs. Path normalization prevents tool arguments from escaping `/workspace`.

## Security controls

Defaults are intentionally diagnostic/read-heavy:

```dotenv
DOCKER_ALLOW_EXEC=false
DOCKER_ALLOW_WRITE=false
OPENWRT_ALLOW_WRITE=false
GOOGLE_GMAIL_WRITE=false
GOOGLE_CALENDAR_WRITE=false
GOOGLE_DRIVE_WRITE=false
```

Enable only the capability you need. Note that access to the Docker socket is inherently privileged at the host level; the application-level write gates reduce accidental use but are not a security boundary against a compromised system-tools container.

The host root mount is read-only. `mcp-system` drops all Linux capabilities except `NET_RAW`, which is required for ping/network diagnostics, and uses `no-new-privileges`.

## Verify

```bash
./scripts/status.sh
```

The status script checks SearXNG search/MCP, Playwright, Memory, System Tools, and the optional Google Workspace MCP endpoint.

For a protocol-only catalog smoke test without Docker:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | node scripts/system-tools.mjs

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | node scripts/google-tools.mjs

node scripts/validate-catalog.mjs
```

## Persistent/local data

```text
data/searxng/     SearXNG configuration
data/playwright/  Chromium profile
data/memory/      Memory MCP JSONL graph (live persistent state)
data/workspace/   Default image/document workspace
data/ssh/         OpenWrt SSH config and keys (ignored by git)
data/google/      Encrypted Google OAuth token state (ignored by git)
secrets/          OAuth client JSON + token-encryption key (ignored by git)
```

## Security MCP

`mcp-security` exposes a bounded red-team/blue-team security toolkit at `http://mcp-security:8935/mcp`. Pi registers the server through native deferred MCP exposure, while Security MCP itself enforces private/allowlisted target policy, typed schemas, runtime bounds, and write/capture gates. Active network/web tools are limited to private or explicitly allowlisted targets by default; typed sqlmap, Metasploit and listener operations are available alongside the scanners.

Core active tools include Nmap discovery/port/service scans, TLS auditing, HTTP security-header checks, Nikto, Nuclei, ffuf content discovery, DNS enumeration/auditing, and dedicated mDNS/DNS-SD, UPnP/SSDP, DHCP/DHCPv6, SNMP, SMB, NTP, LDAP, WS-Discovery, ARP and IPv6 NDP inspection. Passive LLDP, CDP and LLMNR/NBNS observation is also available when packet capture is enabled. Ten high-level network-recon tools (`discover_mdns_subnets`, `get_host_interface_info`, `perform_network_discovery`, `analyze_network_topology`, `analyze_wireless_environment`, `generate_graphical_network_map`, `observe_broadcast_multicast`, `probe_gateway_proxy_arp`, `probe_gateway_hairpin`, `observe_dns_cache`) orchestrate these primitives for newly connected client networks; a required systemd host helper gives them the laptop's real network namespace over a Unix socket without exposing another MCP TCP endpoint. See `docs/NETWORK-RECON-MCP.md` and `docs/CLIENT-ISOLATION-ASSESSMENT.md`. Defensive tools include Trivy, Gitleaks, Semgrep, Syft SBOMs, YARA, ClamAV, tshark/PCAP analysis, optional tcpdump capture, Suricata offline IDS, host log search, IOC search, and Lynis hardening review.

Key controls:

```dotenv
SECURITY_ALLOW_ACTIVE=true
SECURITY_ALLOW_PUBLIC_TARGETS=false
SECURITY_TARGET_ALLOWLIST="127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128,fc00::/7,fe80::/10"
SECURITY_ALLOW_PACKET_CAPTURE=false
```

`SECURITY_TARGET_ALLOWLIST` checks active target addresses; it is an application policy, not a network sandbox. Add a public CIDR/host network only when you are explicitly authorized to assess it. Packet capture is separately disabled by default.

For real laptop Ethernet/Wi-Fi visibility while keeping `mcp-security` on the Docker bridge, install the required Unix-socket host helper:

```bash
./scripts/install-security-host-recon-helper.sh --install-deps
```

The helper exposes only the four host-observation recon operations locally at `/run/mcp-security-host/recon.sock`; graphical map generation stays inside `mcp-security` and writes to the shared MCP workspace. See `docs/NETWORK-RECON-MCP.md` for permissions and package details.

Build/start and validate:

```bash
docker compose build mcp-security
docker compose up -d mcp-security
node scripts/validate-catalog.mjs
./scripts/status.sh
```

Install the stock Pi 1.0 native MCP configuration with:

```bash
./scripts/install-pi-stock-config.sh ~/Projects/pi-docker
```

`pi/APPEND_SYSTEM.md` is deliberately compact and action-oriented. It uses positive instructions for native tool discovery, evidence handling, authorization, credentials, state changes, and responses. The domain-routing section remains for now so a small local model can associate requests with `security`, `system`, `playwright`, `searxng`, `google`, and `memory` while Pi's built-in `tool_search` resolves the exact deferred tool.
### Security image package sources

`mcp-security` is based on Debian Bookworm. Its Dockerfile enables `non-free` for Nikto and `bookworm-backports` for Suricata explicitly; no host APT configuration is required.


## Expanded security CLI suite

The security catalog now has 58 tools. See [SECURITY-SUITE.md](docs/SECURITY-SUITE.md) for the full tool mapping, Firecrawl setup, background jobs, namespace visibility, dependency versions and offline image checks.


### Physical interface provenance

Physical-interface filtering now requires Linux sysfs device backing (`/sys/class/net/<iface>/device`) for non-Wi-Fi Ethernet interfaces; `iw` remains authoritative for Wi-Fi. This deliberately fails closed on ambiguous software links so automatic reconnaissance does not scan virtual/container networks.

## Stock Pi 1.0 integration

Pi-side orchestration is intentionally upstream-native. `scripts/install-pi-stock-config.sh` installs the positive `APPEND_SYSTEM.md` and a native `mcp.json` whose servers use `exposure: "deferred"`. Pi 1.0's built-in `tool_search` discovers deferred MCP tools; the MCP servers own catalog quality, authorization bounds, descriptions, schemas, and metadata.

Owned System, Security, and Google tools include `_meta["ai.catalog"]` metadata with domain, aliases, scope, overlap group, and preferred use. Ambiguous tool families also append concise scope/search terms to their MCP descriptions so Pi's lexical/BM25 tool search can distinguish narrow diagnostics from comprehensive operations.

## Deploy this migration

Install both updated source trees, then run:

```bash
./scripts/deploy-stock-pi-1.0.sh ~/Projects/pi-docker
```

This validates the gateway, rebuilds System and Security (plus Google when configured/running), merges all six native MCP domains into the existing Pi configuration, and upgrades Pi. The merge retains custom server entries, endpoint URLs, authentication headers, timeouts, and explicit disabled states. Source archives omit credentials and runtime state.

Pi remains pinned to 1.0.0, with one narrow fail-closed runtime patch: omitted `tool_search.limit` defaults to 1 instead of 8 so small local models do not accidentally load a broad schema batch. Explicit limits still work. Pi Web UI 0.97.0 also receives the existing compatibility adjustment to load the official MCP/tool-search factories and preserve deferred activation during settings reloads. Start a new conversation after deployment.

## 2026-10-04 recon completion update

Topology preserves partial results when capture is unavailable. Wireless units are explicit. Host observation artifacts feed map input_paths directly. Pi builds now verify the ESM SDK import before deployment. See the bundle RECON-COMPLETION-FIXES.md for validation and limits.

## Dedicated agent workspace

Pi uses `pi-docker/workspace` as `/workspace`. The complete installer aligns the MCP workspace and retains files in the old location. See `docs/WORKSPACE-UPDATE.md`.

## Office and PDF tools

System MCP now provides `pdf_read`, `pdf_write`, `office_read`, `office_edit`, and `office_export`. See `docs/SYSTEM-DOCUMENT-TOOLS.md` for formats, examples, deployment and validation limits.

## Subnet leads from mDNS

Use `discover_mdns_subnets` to collect host-side advertised addresses and candidate network ranges. No candidate is scanned automatically, and heuristic prefixes remain explicit hypotheses. See `docs/MDNS-SUBNETS.md`.
