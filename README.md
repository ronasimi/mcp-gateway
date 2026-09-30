# Local MCP Gateway

Reusable MCP services for Pi and other local/containerized agents.

## Services

```text
mcp-searxng  (upstream ghcr.io/whw23/searxng-http-mcp)
    private mcp-backend network, outbound Internet enabled
            |
            v
mcp-gateway
    :8888 -> SearXNG Web UI + MCP proxy
    :8931 -> Playwright MCP
    :8932 -> Memory MCP
            |
            +-- ai-local -> Pi / trusted containers
            +-- 127.0.0.1 -> host-native agents
```

The upstream SearXNG container is not published to the host and is not attached to `ai-local`, so it does not need an extra API key. The gateway is the only client on its private service network. `mcp-backend` is intentionally **not** an `internal: true` Docker network: SearXNG needs outbound Internet access to query search engines.

## Start

```bash
cp -n .env.example .env
./scripts/init.sh
```

Verify:

```bash
./scripts/status.sh
docker compose logs -f mcp-gateway mcp-searxng
```

## Endpoints

Host-native clients:

```text
http://127.0.0.1:8888/mcp/
http://127.0.0.1:8931/mcp
http://127.0.0.1:8932/mcp
```

Container clients on `ai-local`:

```text
http://mcp-gateway:8888/mcp/
http://mcp-gateway:8931/mcp
http://mcp-gateway:8932/mcp
```

SearXNG Web UI is available at `http://127.0.0.1:8888/`.

## Persistent data

```text
data/playwright/    Chromium profile / cookies / site state
data/memory/        Memory MCP JSONL graph
```

SearXNG uses the upstream image's packaged configuration by default. This avoids stale host-mounted `/etc/searxng` files from older custom builds. If you later need custom SearXNG settings, add a deliberate config mount after validating it against the upstream image version.

## Pi integration

Keep all three servers `directTools: false` in `pi-mcp-adapter` so browser/search/memory schemas remain behind on-demand MCP discovery rather than bloating every model prompt.
