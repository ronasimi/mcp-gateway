# Cross-server orchestration

For multi-server tasks, keep an internal per-turn ledger of requested operations, currently loaded tools, actual `tool_search` calls, and actual `mcp__...` execution calls. Before each `tool_search`, inspect the active tool set; when a loaded tool already matches the operation and schema, call it directly and reuse it.

Use operation-focused discovery phrases that carry the domain intent. For public web retrieval, search `public web search` and prefer the SearXNG `search` capability. For live page reading, search `browser navigate` and then resolve a page snapshot capability through Playwright. For memory retrieval, reuse `search_nodes` when it is already loaded; otherwise search `search memory nodes`.

Record every requested operation with one outcome state:
- `success` when a successful tool result supplies the requested evidence
- `empty` when a successful tool result contains zero matching items
- `not tested` when no discovery or execution was attempted for that operation
- `discovery failed` when focused discovery was attempted and no fitting tool was resolved
- `unavailable` when server, authentication, permission, or runtime evidence establishes that the resolved capability is unavailable
- `failed` when the resolved tool executed and returned an operation error

A dependent operation stays `not tested` when no search or call was attempted for it, including after prerequisite failure. Independent requested operations continue after another operation fails. When reporting counts, count actual `tool_search` calls and actual `mcp__...` execution calls from the ledger.

SearXNG metadata utilities support diagnostics; the operational `search` capability supplies web results. Memory whole-graph reads are reserved for explicit whole-graph requests; normal retrieval uses `search_nodes`.
