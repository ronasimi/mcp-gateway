# Local SearXNG + Playwright MCP Gateway

Standalone third repository for the local AI stack. It intentionally runs as **one container** so the complete stack stays at three long-lived containers:

```text
Ollama project             Pi project                 MCP project
┌─────────────┐           ┌──────────────┐            ┌────────────────────────┐
│ ollama      │◄──────────│ Pi           │───────────►│ mcp-gateway            │
│ :11434      │           │              │  ai-local  │                        │
└─────────────┘           └──────────────┘            │ SearXNG MCP  :8888    │
                                                     │ Playwright MCP :8931   │
                                                     │ Chromium (headless)    │
                                                     └────────────────────────┘
```

The image uses the self-contained `ghcr.io/whw23/searxng-http-mcp` application on a full Void Linux/musl runtime, then adds Microsoft's official `@playwright/mcp` plus system Chromium. Current SearXNG container images use a stripped Void runtime rather than Alpine, so the Dockerfile deliberately uses XBPS instead of `apk`. Pi gets private metasearch and browser automation without a fourth worker container.

## MCP endpoints

Pi connects over the external `ai-local` Docker network:

```text
SearXNG:    http://mcp-gateway:8888/mcp/
Playwright: http://mcp-gateway:8931/mcp
```

Host-only diagnostics are bound to loopback:

```text
SearXNG:    http://127.0.0.1:8811/mcp/
Playwright: http://127.0.0.1:8931/mcp
SearXNG UI: http://127.0.0.1:8811/
```

The SearXNG endpoint and UI require the generated `x-api-key`. Playwright is **not exposed to the LAN**; it is reachable only from localhost and containers attached to `ai-local`.

## Capabilities

### SearXNG MCP

The bundled SearXNG MCP intentionally has a small surface:

- `search` — private metasearch across SearXNG engines
- `autocomplete` — query suggestions
- `engine_info` — available engines and categories

### Playwright MCP

Microsoft's Playwright MCP provides browser navigation and interaction using structured accessibility snapshots, including navigation, clicking, typing, snapshots, tabs, screenshots, and related browser operations.

The browser is configured as:

- headless Chromium;
- system Chromium from the container, so no first-run browser download is needed;
- persistent browser profile in a Docker volume;
- five-minute idle close by default;
- no code-generation payloads;
- no Chromium sandbox because the process runs inside the container with `no-new-privileges`.

## Start

```bash
cp .env.example .env        # optional; init.sh does this automatically
./scripts/init.sh
```

`init.sh`:

1. creates a random 256-bit SearXNG MCP API key when needed;
2. creates the external `ai-local` Docker network;
3. builds the combined SearXNG + Playwright MCP image;
4. starts the single MCP container.

Check both endpoints:

```bash
./scripts/status.sh
```

Stop it:

```bash
./scripts/down.sh
```

Print the SearXNG API key:

```bash
./scripts/token.sh
```

## Pi integration

Pi and this MCP service are separate Compose projects. Attach Pi to `ai-local` using `pi/compose-snippet.yaml`.

Copy the generated token into the Pi project's `.env`:

```bash
MCP_GATEWAY_AUTH_TOKEN=$(./scripts/token.sh)
```

Then adapt `pi/mcp-adapter.json.example` into Pi's MCP configuration. It defines two logical MCP servers pointing to the **same container**:

```json
{
  "mcpServers": {
    "searxng": {
      "url": "http://mcp-gateway:8888/mcp/",
      "headers": {
        "x-api-key": "${MCP_GATEWAY_AUTH_TOKEN}"
      },
      "directTools": false
    },
    "playwright": {
      "url": "http://mcp-gateway:8931/mcp",
      "directTools": false
    }
  }
}
```

Keep `directTools` disabled. Pi should see only its compact MCP proxy and discover SearXNG/Playwright capabilities on demand instead of injecting Playwright's relatively large browser schema set into every model request.

## Persistence

Two named Docker volumes are used:

```text
searxng_config       /etc/searxng
playwright_profile   /data/playwright
```

The Playwright profile preserves cookies and local storage across container restarts. Remove that volume if you want a completely clean browser session.

## Security

- SearXNG MCP/UI uses a random API key.
- Both host ports bind only to `127.0.0.1`.
- Pi communicates over the private `ai-local` network.
- `.env` is ignored by Git.
- No Docker socket is mounted.
- Playwright has powerful browser capabilities, so do not attach untrusted containers to `ai-local`.
- Playwright's host allowlist is disabled to permit Docker service-name routing; network isolation, not that allowlist, is the boundary here.

## Resource limits

Chromium needs more headroom than search alone. Defaults are:

```text
Memory:       1536 MiB
CPU:          2 cores
Shared memory: 512 MiB
```

Tune them in `.env`:

```bash
MCP_GATEWAY_MEMORY=1536m
MCP_GATEWAY_CPUS=2.0
PLAYWRIGHT_SHM_SIZE=512m
```

For the Ryzen 4650U/16 GB host this keeps the browser bounded while leaving most memory available to Ollama.

## Logs

```bash
docker compose logs -f mcp-gateway
```

## Update

Rebuild against the newest SearXNG base image while retaining the pinned Playwright MCP package version in the Dockerfile:

```bash
docker compose build --pull --no-cache
docker compose up -d
```

To deliberately update Playwright MCP, change the pinned `@playwright/mcp` version in `Dockerfile`, rebuild, and test before committing.
