# Local MCP gateway

A local MCP stack for Pi with **bounded/semantic tool discovery**. The normal model prompt stays small: MCP tools are not exposed directly and are granted only after `mcp_search` finds a relevant capability.

## Services

| Service | Endpoint | Purpose |
|---|---|---|
| SearXNG MCP | `127.0.0.1:8888/mcp/` | Web search |
| Playwright MCP | `127.0.0.1:8931/mcp` | Browser navigation, snapshots, screenshots |
| Memory MCP | `127.0.0.1:8932/mcp` | Persistent graph memory |
| System Tools MCP | `127.0.0.1:8933/mcp` | Docker, host, network, OpenWrt, image, document tools |

Containers on the external `ai-local` network use `mcp-searxng:8888`, `mcp-gateway:8931/8932`, and `mcp-system:8933`.

## Bounded discovery

`pi/mcp-adapter.json.example` deliberately sets `directTools: false` for every MCP server. The system-tools server advertises a broad catalog, but Pi only receives a bounded search result and per-turn grant for tools relevant to the current request.

The catalog is optimized for semantic/lexical discovery in two layers:

1. **Tool names and MCP descriptions** use explicit domain + action names such as `docker_container_logs`, `network_dns_lookup`, `openwrt_uci_get`, `image_resize`, and `document_extract_text`.
2. **`searchKeywords` aliases** add likely user/model phrasing such as `docker logs`, `container error`, `router clients`, `wifi status`, `find in pdf`, `resize image`, `host memory`, and `port scan`.

This keeps all 53 system-tool schemas out of the steady-state prompt while making them easy for a small local model to retrieve.

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

`docker_exec` is disabled by default with `DOCKER_ALLOW_EXEC=false`. Lifecycle/removal operations are disabled by default with `DOCKER_ALLOW_WRITE=false`.

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

## Install / update

```bash
./scripts/init.sh
```

The initializer:

- creates the external `ai-local` network if required;
- creates persistent SearXNG, Playwright, Memory, workspace, and SSH directories;
- generates `SEARXNG_SECRET`;
- builds the Playwright/Memory and System Tools images;
- starts the stack;
- runs the status checks.

Then merge/copy `pi/mcp-adapter.json.example` into Pi's MCP adapter configuration and restart Pi.

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
```

Enable only the capability you need. Note that access to the Docker socket is inherently privileged at the host level; the application-level write gates reduce accidental use but are not a security boundary against a compromised system-tools container.

The host root mount is read-only. `mcp-system` drops all Linux capabilities except `NET_RAW`, which is required for ping/network diagnostics, and uses `no-new-privileges`.

## Verify

```bash
./scripts/status.sh
```

The status script checks SearXNG search/MCP, Playwright, Memory, and the System Tools MCP endpoint.

For a protocol-only catalog smoke test without Docker:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | node scripts/system-tools.mjs
```

## Persistent/local data

```text
data/searxng/     SearXNG configuration
data/playwright/  Chromium profile
data/memory/      Memory MCP JSONL graph
data/workspace/   Default image/document workspace
data/ssh/         OpenWrt SSH config and keys (ignored by git)
```
