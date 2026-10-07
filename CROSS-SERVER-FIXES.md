# Cross-server discovery fixes (Phase 1.1)

This update is a targeted follow-up to the atomic Phase 1 refactor. It keeps the owned MCP tool catalogs and public tool names unchanged.

## Changes

1. **SearXNG discovery hygiene**
   - Pi hides `engine_info` and `autocomplete` from normal deferred discovery.
   - `search` remains deferred and the server description identifies it as the operational retrieval capability.

2. **Memory retrieval hygiene**
   - Pi hides `read_graph` from normal deferred discovery.
   - `search_nodes` remains deferred and is named in the server description as the preferred retrieval capability.

3. **Calendar upcoming-event semantics**
   - `calendar_list_events` now defaults an omitted `time_min` to the current instant.
   - Results include `effective_time_min` and `time_min_defaulted` so the lower bound is observable.
   - An explicit `time_min` is preserved unchanged.

4. **Cross-server execution contract**
   - Pi reuses a fitting already-loaded tool before another `tool_search`.
   - Discovery queries carry domain intent (`public web search`, `browser navigate`, `search memory nodes`).
   - Requested operations are tracked as `success`, `empty`, `not tested`, `discovery failed`, `unavailable`, or `failed`.
   - Tool-count summaries use actual `tool_search` calls and actual `mcp__...` executions.

## Persistence and credentials

The updater merges Pi's `mcp.json` and patches the existing prompt in place. It does not replace `.env`, `compose.yaml`, `data/`, `data/google/`, Google OAuth material, or API keys.
