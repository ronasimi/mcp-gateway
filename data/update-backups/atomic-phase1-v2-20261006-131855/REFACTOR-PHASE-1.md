# Atomic server refactor — Phase 1

Phase 1 is intentionally behavior-preserving. It establishes module boundaries before any public MCP namespace changes.

## Implemented

- Added shared `src/core/schema.mjs` schema primitives.
- Added shared `src/core/mcp-stdio.mjs` MCP/JSON-RPC stdio dispatcher.
- Added `src/adapters/host-recon-client.mjs` for host-helper delegation.
- Split mDNS into wire, collection, normalization, inference, IP/range, and reporting modules.
- Split network-recon schemas, helpers, artifact handling, and orchestration.
- Replaced legacy mDNS/network files with compatibility entrypoints preserving existing exports.
- Moved System, Security, and Google onto the common MCP stdio dispatcher without changing their domain policies.
- Updated System/Security/Google images to include the shared source tree.
- Updated the host-helper installer to deploy the same atomized source tree.

## Deliberately unchanged

- Public MCP tool names and schemas.
- Existing server endpoints and Pi MCP configuration.
- Security authorization gates.
- Result-size limits and artifact behavior.
- Network collection behavior.

## Next

Phase 2 should split `src/domains/network/recon/service.mjs` into independent host-state, discovery, mDNS orchestration, topology, wireless, and map services. The existing `createNetworkRecon()` service becomes a small dispatcher/composition root.
