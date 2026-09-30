# Local SearXNG + Playwright + Memory MCP Gateway

Standalone third repository for the local AI stack. It intentionally runs as **one container** so the complete stack stays at three long-lived containers:

```text
Ollama project             Pi project                 MCP project
┌─────────────┐           ┌──────────────┐            ┌─────────────────────────┐
│ ollama      │◄──────────│ Pi           │───────────►│ mcp-gateway             │
│ :11434      │           │              │  ai-local  │                         │
└─────────────┘           └──────────────┘            │ SearXNG MCP    :8888   │
                                                     │ Playwright MCP :8931   │
                                                     │ Memory MCP     :8932   │
                                                     │ Chromium (headless)     │
                                                     └─────────────────────────┘
```

The image combines the self-contained `ghcr.io/whw23/searxng-http-mcp` application with Microsoft's Playwright MCP and the official Model Context Protocol Memory server. The Memory server is stdio-native, so Supergateway exposes it as Streamable HTTP without adding another container.

## MCP endpoints

Containerized agents attached to the external `ai-local` Docker network use:

```text
SearXNG:    http://mcp-gateway:8888/mcp/
Playwright: http://mcp-gateway:8931/mcp
Memory:     http://mcp-gateway:8932/mcp
```

Host-native MCP clients use the loopback-published endpoints:

```text
SearXNG:    http://127.0.0.1:8888/mcp/
Playwright: http://127.0.0.1:8931/mcp
Memory:     http://127.0.0.1:8932/mcp
SearXNG UI: http://127.0.0.1:8888/
```

None of these ports are published to the LAN. SearXNG requires the generated `x-api-key`. Playwright and Memory rely on loopback/private-Docker-network isolation, so do not attach untrusted containers to `ai-local`.

## Capabilities

### SearXNG MCP

- `search` — private metasearch across SearXNG engines
- `autocomplete` — query suggestions
- `engine_info` — available engines and categories

### Playwright MCP

Browser navigation and interaction through structured accessibility snapshots, including navigation, clicking, typing, snapshots, tabs and screenshots. Chromium runs headless with a persistent profile.

### Memory MCP

The official MCP Memory server provides a small persistent knowledge graph. Its core operations include:

- creating and deleting entities;
- creating and deleting directed relations;
- adding and deleting observations/facts;
- searching nodes;
- opening selected nodes;
- reading the graph.

The graph is shared by every MCP client that connects to this endpoint. This makes it suitable for durable agent facts, project decisions, machine configuration, recurring preferences and cross-session knowledge. It is not an embedding/vector database; retrieval is knowledge-graph/text based.

Memory is stored on the host at:

```text
./data/memory/memory.jsonl
```

and mounted into the container at `/data/memory/memory.jsonl`. The directory is ignored by Git except for `.gitkeep`.

## Start

```bash
cp .env.example .env        # optional; init.sh does this automatically
./scripts/init.sh
```

`init.sh`:

1. creates a random 256-bit SearXNG MCP API key when needed;
2. creates `./data/memory` for durable Memory MCP state;
3. creates the external `ai-local` Docker network;
4. builds the combined MCP image;
5. starts the single MCP container.

Check all endpoints:

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

Copy the generated SearXNG token into the Pi project's `.env`:

```bash
MCP_GATEWAY_AUTH_TOKEN=$(./scripts/token.sh)
```

Then adapt `pi/mcp-adapter.json.example` into Pi's MCP configuration. It defines three logical MCP servers pointing to the **same container**:

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
    },
    "memory": {
      "url": "http://mcp-gateway:8932/mcp",
      "directTools": false
    }
  }
}
```

Keep `directTools` disabled. Pi should see only its compact MCP proxy and discover search/browser/memory capabilities on demand instead of injecting their schemas into every model request.

## Other MCP clients

The services are standard HTTP MCP endpoints and are not Pi-specific. Any compatible local agent can use the loopback URLs; any compatible container on `ai-local` can use the Docker service-name URLs.

Example host-native configuration:

```json
{
  "mcpServers": {
    "searxng": {
      "url": "http://127.0.0.1:8888/mcp/",
      "headers": {
        "x-api-key": "<MCP_GATEWAY_AUTH_TOKEN>"
      }
    },
    "playwright": {
      "url": "http://127.0.0.1:8931/mcp"
    },
    "memory": {
      "url": "http://127.0.0.1:8932/mcp"
    }
  }
}
```

## Persistence

Persistent state is split by purpose:

```text
searxng_config                 /etc/searxng
playwright_profile             /data/playwright
./data/memory/                 /data/memory
```

The Memory knowledge graph is deliberately a bind mount rather than a named volume so it is easy to inspect, back up and version separately if desired.

A simple backup is:

```bash
cp -a data/memory "data/memory.backup.$(date +%Y%m%d-%H%M%S)"
```

## Security

- SearXNG MCP/UI uses a random API key.
- All host ports bind only to `127.0.0.1`.
- Pi communicates over the private `ai-local` network.
- `.env` and Memory data are ignored by Git.
- No Docker socket is mounted.
- Playwright has powerful browser capabilities.
- Memory can contain sensitive durable facts; treat `data/memory/memory.jsonl` as private data.
- Playwright and Memory currently rely on loopback/private-network isolation rather than endpoint authentication.

## Resource limits

Defaults remain:

```text
Memory:        1536 MiB
CPU:           2 cores
Shared memory: 512 MiB
```

Memory MCP itself is small compared with Chromium and should not materially change the resource budget.

Tune limits in `.env` if needed.

## Logs

```bash
docker compose logs -f mcp-gateway
```

## Updating

Rebuild against the newest SearXNG base image while retaining the pinned MCP package versions in `Dockerfile`:

```bash
docker compose build --pull --no-cache
docker compose up -d
```

The current image pins:

```text
@playwright/mcp                    0.0.83
@modelcontextprotocol/server-memory 2026.8.31
supergateway                        4.0.0
```

Update these deliberately and test before committing.
