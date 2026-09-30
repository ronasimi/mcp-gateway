# Local MCP services

A single Docker container providing three MCP services for local/container agents:

- **SearXNG MCP** — `http://mcp-gateway:8888/mcp`
- **Playwright MCP** — `http://mcp-gateway:8931/mcp`
- **Memory MCP** — `http://mcp-gateway:8932/mcp`

Host-native clients use the same ports at `127.0.0.1`. All host bindings are loopback-only.

## Why this image is built from Debian/Python 3.14

SearXNG's production image is intentionally stripped and is not intended to be extended with a distro package manager. Earlier variants that tried to add Alpine `apk` or restore Void `xbps` were brittle. This repo instead installs all runtimes on one `python:3.14-slim-bookworm` base: SearXNG, `searxng-http-mcp`, Node.js, Chromium, Playwright MCP, Memory MCP, and Supergateway.

Upstream SearXNG is pinned by `SEARXNG_REF` (default `12f8b6515`).

## Start

```bash
cp -n .env.example .env
./scripts/init.sh
```

Then:

```bash
./scripts/status.sh
docker compose logs -f mcp-gateway
```

## Persistent host data

```text
data/searxng/       SearXNG settings
data/playwright/    Chromium profile
data/memory/        Memory MCP JSONL graph
```

## Endpoints

Container clients on the external `ai-local` network:

```text
http://mcp-gateway:8888/mcp
http://mcp-gateway:8931/mcp
http://mcp-gateway:8932/mcp
```

Host-native clients:

```text
http://127.0.0.1:8888/mcp
http://127.0.0.1:8931/mcp
http://127.0.0.1:8932/mcp
```

These endpoints are intentionally not LAN-published. Treat `ai-local` as a trusted local Docker network.

## Pi

Use `pi/mcp-adapter.json.example` with `pi-mcp-adapter`. All three servers use `directTools: false` so tool schemas stay behind MCP discovery rather than entering every model request.
