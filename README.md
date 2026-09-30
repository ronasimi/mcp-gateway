# Local MCP services

A single Docker container providing three MCP services for local/container agents:

- **SearXNG MCP** — `http://mcp-gateway:8888/mcp`
- **Playwright MCP** — `http://mcp-gateway:8931/mcp`
- **Memory MCP** — `http://mcp-gateway:8932/mcp`

Host-native clients use the same ports at `127.0.0.1`. All host bindings are loopback-only.


### Build/runtime design

The image uses one Debian base but **two Python runtimes on purpose**:

- Debian Python 3.11 runs pinned SearXNG from its source tree.
- CPython 3.14 from the base image runs `searxng-http-mcp`, which requires Python 3.14+.

SearXNG is not installed with `pip install .`. Instead, its pinned runtime requirements are installed into `/opt/searxng-venv` and the application runs directly from `/opt/searxng-src`. This avoids SearXNG `setup.py` importing the application during package metadata generation and removes the build-time dependency on runtime `/etc/searxng/settings.yml`. The runtime entrypoint creates the durable settings file before starting SearXNG.

Upstream SearXNG is pinned by `SEARXNG_REF` (default `12f8b6515`, corresponding to the official `2026.9.25-12f8b6515` build). The Docker build clones the `master` commit history with `--filter=blob:none` and resolves the abbreviated revision locally. This avoids GitHub's refusal to fetch an abbreviated SHA directly while preserving a reproducible SearXNG revision.

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

### SearXNG revision checkout

`SEARXNG_REF` may be an abbreviated commit ID such as `12f8b6515`. Do not replace the Dockerfile checkout with `git fetch origin "$SEARXNG_REF"`: GitHub does not advertise abbreviated commit IDs as remote refs. The image intentionally retrieves the filtered `master` history first and resolves the pinned commit locally.
