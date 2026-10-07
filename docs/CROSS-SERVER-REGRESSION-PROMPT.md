# Cross-server regression prompt

Perform this read-only cross-server check and continue through all independent steps.

Maintain an internal ledger of loaded tools, actual `tool_search` calls, and actual `mcp__...` execution calls. Before each discovery call, reuse a fitting loaded tool when one is already active.

1. **Web search** — discover `public web search` with `limit: 1`. The expected operational capability is SearXNG search rather than engine metadata or autocomplete. Search for `latest Linux kernel stable release official kernel.org` and return the best official result.
2. **Browser** — discover `browser navigate` with `limit: 1`, open the official kernel.org result, then discover/use the appropriate page snapshot capability and report the stable version visible on the live page.
3. **Calendar** — discover `upcoming google calendar events` with `limit: 1`. Call the returned tool with `max_results: 3` and omit `time_min`. Report `effective_time_min`, `time_min_defaulted`, and the next three events. The default lower bound should be the current time.
4. **Memory** — if `search_nodes` is already loaded, call it directly. Otherwise discover `search memory nodes` with `limit: 1`, then search for `Pi Docker`. Report `empty` when a successful query returns no entities/relations.

For each step use exactly one outcome state: `success`, `empty`, `not tested`, `discovery failed`, `unavailable`, or `failed`. A step with no discovery/execution attempt is `not tested`, including when a prerequisite prevents it.

Finish with a four-row audit table containing the exact tool used and outcome. Then report the actual number of `tool_search` calls and actual number of `mcp__...` execution calls. Do not infer counts from the number of requested steps.
