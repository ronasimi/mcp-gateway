# Cross-server discovery hardening

This update keeps the existing MCP servers and public owned-tool catalogs intact while reducing cross-domain discovery noise.

- Pi hides SearXNG `engine_info` and `autocomplete` from normal deferred discovery and keeps `search` deferred.
- Pi hides Memory `read_graph` from normal deferred discovery and keeps `search_nodes` deferred.
- Server descriptions explicitly identify the operational retrieval tool so Pi can rank it with domain context.
- Calendar event listing defaults an omitted `time_min` to the current instant and reports `effective_time_min` plus `time_min_defaulted`.
- The managed prompt section tracks loaded-tool reuse, actual discovery/execution counts, and six operation outcome states: success, empty, not tested, discovery failed, unavailable, and failed.

The exposure changes are Pi-side only; SearXNG and Memory storage/services are unchanged. Google credentials and tokens remain in their existing persistent stores.
