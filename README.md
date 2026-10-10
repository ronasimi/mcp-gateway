<div align="center">

# 🧰 MCP Gateway

**Purpose-built tools for a local Pi agent.**

`Six domains` · `Deferred discovery` · `Bounded execution` · `Server-side credentials`

[Quick start](#quick-start) · [Operations](docs/OPERATIONS.md) · [Network tools](docs/NETWORK.md) · [Development](docs/DEVELOPMENT.md) · [Catalog](docs/TOOL-CATALOG.md)

</div>

The gateway supplies browser, search, memory, host, account and security capabilities. Each owned MCP server publishes strict schemas, concise discovery metadata and execution bounds. Pi r24 owns the agent loop and tool invocation contract in its separate repo.

## Services

| Domain | Container endpoint | Host port | Capabilities |
| :--- | :--- | :--- | :--- |
| Search | `mcp-searxng:8888/mcp/` | 8888 | Public web search |
| Browser | `mcp-gateway:8931/mcp` | 8931 | Playwright navigation, snapshots and screenshots |
| Memory | `mcp-gateway:8932/mcp` | 8932 | Persistent graph memory |
| System | `mcp-system:8933/mcp` | 8933 | Docker, host, OpenWrt, images, PDF and Office |
| Google | `mcp-google:8934/mcp` | 8934 | Gmail, Calendar and Drive; optional OAuth profile |
| Security | `mcp-security:8935/mcp` | 8935 | Authorized assessment, passive observations and mapping |

MCP host endpoints bind to localhost. Services share the external `ai-local` network with Pi. Google starts only when configured.

## Quick start

```bash
cd ~/Projects/mcp-gateway
bash scripts/init.sh
```

The initializer creates local settings, persistent directories and secrets, builds the services and starts the stack. Existing configuration is retained. To share Pi's workspace, set this in `.env` before starting:

```dotenv
MCP_WORKSPACE_PATH=/home/ron/Projects/pi-docker/workspace
```

Physical-network tools also need the [host helper](docs/NETWORK.md#host-helper). Existing installations should refresh it after replacing gateway source.

## What runs where

| Operation | Execution boundary |
| :--- | :--- |
| Host inventory | System's read-only host mount |
| Docker diagnostics | System's Docker socket |
| OpenWrt status | Configured SSH target such as Anansi or Arachne |
| Laptop interfaces and LAN observations | Security's Unix-socket host helper |
| Generic network probes | The owning container's network namespace |
| Image, document and map outputs | Shared `/workspace` |
| Account requests | Google container with server-side OAuth material |

Container routes and interfaces do not describe the physical LAN. `openwrt_targets` discovers real SSH aliases; `openwrt_status` returns structured router observations.

## Evidence that fits the context

Large observations are saved under `.security-results` and returned as compact reports. `read_security_result` retrieves bounded selected fields from saved JSON without collecting new infrastructure observations. Credential redaction happens before MCP encoding. Pi's `result_get` retrieves its own archives; the two readers have distinct reference and path boundaries.

## Daily commands

```bash
bash scripts/status.sh
node scripts/validate-catalog.mjs
docker compose logs --tail=100 mcp-security
docker compose exec -T mcp-security node /opt/mcp/verify-security-startup.mjs
```

The Security image now checks **initialize + tools/list** during its build. This catches missing imports such as `src/core/redact.mjs`. HTTP listener health alone does not establish a working MCP process.

## Development

```bash
bash scripts/check.sh
```

The check runs current Node and Python suites, validates owned catalogs and checks Security startup without executing scans. [Development](docs/DEVELOPMENT.md) describes prerequisites, environment-dependent skips and source boundaries.

[Setup, credentials and troubleshooting →](docs/OPERATIONS.md)

## Bounded Masscan

Security includes `masscan_scan` for explicit authorized IPv4 TCP SYN scans, alongside Nmap `port_scan` for service detection. Rate, address/port count, total probes and process duration are bounded. It uses the Security-container namespace; passive physical LAN observation remains a separate operation. See [usage and limits](docs/NETWORK.md#masscan).
