# MCP gateway architecture

The gateway follows one rule: **atomic code, task-level MCP tools, workflow-level skills**.

## Layers

### `src/core/`
Transport- and domain-neutral primitives. `mcp-stdio.mjs` owns JSON-RPC/MCP stdio framing and dispatch. Domain processes inject their catalogs, validation, execution policy, result encoding, and error encoding.

### `src/adapters/`
Bounded interfaces to operating-system or external runtimes. Adapters do not define model-facing MCP schemas. `host-recon-client.mjs` is the Unix-socket client used by host-network operations.

### `src/domains/`
Implementation grouped by capability. Domain code may compose core primitives and adapters, but it does not own the MCP transport loop.

The first migrated domain is `network`:

- `network/mdns/wire.mjs` — DNS wire parsing/query construction
- `network/mdns/collector.mjs` — bounded multicast collection
- `network/mdns/normalize.mjs` — DNS-SD joins and advertised-host normalization
- `network/mdns/infer.mjs` — candidate network inference
- `network/mdns/ip.mjs` — address/range/scope primitives
- `network/mdns/report.mjs` — compact model-facing reporting projection
- `network/recon/tools.mjs` — public task-level schemas
- `network/recon/helpers.mjs` — parsers and pure helpers
- `network/recon/artifacts.mjs` — artifact/map input normalization
- `network/recon/service.mjs` — orchestration compatibility service

### `scripts/`
Runtime entrypoints and compatibility shims. Existing filenames and exports are deliberately preserved so Docker images, tests, the host helper, and Pi MCP configuration do not change during structural refactors.

`system-tools.mjs`, `security-tools.mjs`, and `google-tools.mjs` share the same `core/mcp-stdio.mjs` transport primitive while keeping their own policy and result handling.

## Dependency direction

```text
scripts (entrypoints / compatibility)
        |
        v
src/domains ----------------> src/adapters
        |                         |
        +------------+------------+
                     v
                 src/core
```

Core must never import a domain. Adapters must not import model-facing tool catalogs. Domain modules should not import the top-level server entrypoints.

## Public API policy

Structural refactors must not silently rename or multiply model-facing tools. Existing public MCP names and schemas stay stable until an explicit migration changes a domain boundary. Internal primitives such as DNS packet parsing are library functions, not separate tools.

## Large-result policy

Collectors preserve full evidence in artifacts and return compact task-oriented reports. Raw evidence is retrieved only when needed. This keeps the model context bounded while retaining auditability.

## Planned sequence

1. **Foundation / network atomization** — core transport, adapters, mDNS and network modules; public API unchanged.
2. **Network orchestration split** — split the remaining network service into host-state, discovery, topology, wireless, and map services.
3. **Domain registries** — move System, Security, and Google schema/handler groups behind thin registries using the common core transport.
4. **Network server boundary** — introduce a dedicated `network` MCP service with compatibility aliases/migration from Security.
5. **New workstation domains** — Files, Documents, Search, Images/Vision, Structured Data, and Git.
