# Local MCP gateway

A local MCP stack for Pi with **bounded/semantic tool discovery**. The normal model prompt stays small: MCP tools are not exposed directly and are granted only after `mcp_search` finds a relevant capability.

## Services

| Service | Endpoint | Purpose |
|---|---|---|
| SearXNG MCP | `127.0.0.1:8888/mcp/` | Web search |
| Playwright MCP | `127.0.0.1:8931/mcp` | Browser navigation, snapshots, screenshots |
| Memory MCP | `127.0.0.1:8932/mcp` | Persistent graph memory |
| System Tools MCP | `127.0.0.1:8933/mcp` | Docker, host, network, OpenWrt, image, and document tools |
| Google Workspace MCP | `127.0.0.1:8934/mcp` | Gmail, Calendar, and Drive account tools (optional) |

Containers on the external `ai-local` network use `mcp-searxng:8888`, `mcp-gateway:8931/8932`, and `mcp-system:8933`. When enabled, Google Workspace is `mcp-google:8934`.

## Bounded discovery

`pi/mcp-adapter.json.example` deliberately sets `directTools: false` for every MCP server. The system-tools server advertises a broad catalog, but Pi only receives a bounded search result and per-turn grant for tools relevant to the current request.

The catalog is optimized for semantic/lexical discovery in two layers:

1. **Tool names and MCP descriptions** use explicit domain + action names such as `docker_container_logs`, `network_dns_lookup`, `openwrt_uci_get`, `image_resize`, and `document_extract_text`.
2. **`searchKeywords` aliases** add likely user/model phrasing such as `docker logs`, `container error`, `router clients`, `wifi status`, `find in pdf`, `resize image`, `host memory`, and `port scan`.

This keeps all 53 system-tool schemas and all 23 Google Workspace schemas out of the steady-state prompt while making them easy for a small local model to retrieve. Tool definitions also include MCP read-only/destructive/idempotent/open-world annotations where applicable.

## System tools

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
- `host_network_info`
- `host_disk_usage`
- `host_read_file`

`host_read_file` is restricted to `/etc`, `/proc`, `/sys`, `/var/log`, and `/run` and rejects binary files.

### Network

- `network_dns_lookup`
- `network_ping`
- `network_trace_route`
- `network_http_probe`
- `network_port_check`
- `network_scan_ports`
- `network_interfaces`

The scanner is intentionally bounded (`nmap --host-timeout 45s`, one target supplied per call) to prevent a discovery request from turning into an unbounded scan.

### OpenWrt

OpenWrt access is SSH-key/config based. The model refers to a configured SSH alias instead of receiving credentials in a tool call.

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

Image tools are restricted to `MCP_WORKSPACE_PATH` and use ImageMagick/ExifTool.

- `image_list`
- `image_info`
- `image_metadata`
- `image_resize`
- `image_crop`
- `image_convert`
- `image_compare`
- `image_thumbnail`

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

Then merge/copy `pi/mcp-adapter.json.example` into Pi's MCP adapter configuration, use `pi/APPEND_SYSTEM.md` as the bounded-discovery prompt fragment, and restart Pi. For the standard `~/Projects/pi-docker` layout, `./scripts/install-pi-bounded-config.sh` backs up and updates both files and also patches the older native `mcp_search` description when that source is present on the host.

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

`mcp-security` exposes a bounded red-team/blue-team security toolkit at `http://mcp-security:8935/mcp`. Schemas remain behind `mcp_search` (`directTools=false`). Active network/web tools are limited to private or explicitly allowlisted targets by default; the server does not expose arbitrary shell, credential spraying, password cracking, persistence, or exploit-payload execution.

Core active tools include Nmap discovery/port/service scans, TLS auditing, HTTP security-header checks, Nikto, Nuclei, ffuf content discovery, and DNS enumeration. Defensive tools include Trivy, Gitleaks, Semgrep, Syft SBOMs, YARA, ClamAV, tshark/PCAP analysis, optional tcpdump capture, Suricata offline IDS, host log search, IOC search, and Lynis hardening review.

Key controls:

```dotenv
SECURITY_ALLOW_ACTIVE=true
SECURITY_ALLOW_PUBLIC_TARGETS=false
SECURITY_TARGET_ALLOWLIST="127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128,fc00::/7,fe80::/10"
SECURITY_ALLOW_PACKET_CAPTURE=false
```

`SECURITY_TARGET_ALLOWLIST` is the enforcement boundary for active scans. Add a public CIDR/host network only when you are explicitly authorized to assess it. Packet capture is separately disabled by default.

Build/start and validate:

```bash
docker compose build mcp-security
docker compose up -d mcp-security
node scripts/validate-catalog.mjs
./scripts/status.sh
```

Install the updated Pi bounded-discovery configuration with:

```bash
./scripts/install-pi-bounded-config.sh ~/Projects/pi-docker
```

### Pi / WhiteRabbitNeo prompt compatibility

The Pi addendum distinguishes domain knowledge from runtime execution tools so security-oriented models do not answer a request for a security-tool wishlist with Pi's internal `read`/`bash`/`mcp_*` interfaces. It also forbids inventing model provider, cutoff, or family metadata.

`./scripts/install-pi-bounded-config.sh ~/Projects/pi-docker` now also attempts to patch two known native Pi prompt strings in the host checkout, while backing up every changed source file with a timestamped `.bak.*` suffix:

- the generic `expert coding assistant` preamble becomes model-neutral;
- the native `mcp_search` description advertises `security`, `system`, `google`, `playwright`, `searxng`, and `memory`.

Reference replacements are stored in `pi/BASE_PREAMBLE.txt` and `pi/MCP_SEARCH_DESCRIPTION.txt`. If your Pi version generates those strings elsewhere, use the reference files to update that source manually.

For the manually selected WhiteRabbitNeo security model, `pi/Modelfile.whiterabbitneo` provides the recommended 16K-context system prompt. It identifies the local role without claiming a remote provider and tells the model to distinguish security knowledge from executable runtime tools.

