# Local MCP stack

This repository provides three MCP capabilities using two containers:

- **SearXNG MCP + Web UI** — upstream `ghcr.io/whw23/searxng-http-mcp` image, exposed directly on `127.0.0.1:8888` and `mcp-searxng:8888` on `ai-local`.
- **Playwright MCP** — `127.0.0.1:8931` / `mcp-gateway:8931`.
- **Memory MCP** — `127.0.0.1:8932` / `mcp-gateway:8932`, persisted in `data/memory/memory.jsonl`.

## Why SearXNG is direct

The upstream SearXNG MCP image already multiplexes its Web UI and `/mcp/` endpoint on port 8888. Putting another HTTP reverse proxy in front of it caused browser `/search` POST/GET requests to be treated differently from direct requests and made 403 failures harder to diagnose. v11 publishes the upstream container directly instead.

The local SearXNG overlay explicitly keeps both `html` and `json` search formats enabled and disables SearXNG's public-instance limiter. The SearXNG Search API returns 403 when a requested format is not enabled, so both formats are required for browser + MCP use.

## Initialize

```bash
./scripts/init.sh
```

The script creates `ai-local` if necessary, generates `SEARXNG_SECRET`, seeds `data/searxng/settings.yml`, pulls the upstream SearXNG image, builds the Playwright/Memory image, and starts the stack.

## Endpoints

Host/native clients:

```text
SearXNG MCP     http://127.0.0.1:8888/mcp/
SearXNG Web UI  http://127.0.0.1:8888/
Playwright MCP  http://127.0.0.1:8931/mcp
Memory MCP      http://127.0.0.1:8932/mcp
```

Containers attached to `ai-local`:

```text
SearXNG MCP     http://mcp-searxng:8888/mcp/
Playwright MCP  http://mcp-gateway:8931/mcp
Memory MCP      http://mcp-gateway:8932/mcp
```

## Verify

```bash
./scripts/status.sh
```

It checks the SearXNG root, performs a real HTML `/search` request, checks the MCP listener, prints the relevant persisted settings, and checks Playwright/Memory.

## Persistent data

```text
data/searxng/     SearXNG settings
data/playwright/  Chromium profile
data/memory/      Memory MCP JSONL graph
```
