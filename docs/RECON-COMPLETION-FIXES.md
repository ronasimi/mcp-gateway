# Recon completion fixes — 2026-10-04

The latest run loaded the corrected catalog and collected real host, LAN and passive wireless observations. It failed optional L2 capture twice and stopped with a thinking-only response before generating its map.

Changes:
- Denied optional LLDP/CDP capture returns base topology with l2_discovery.status=unavailable and complete=false. Capture permissions remain enforced; no capture runs after denial.
- Nearby APs expose signal_percent and signal_dbm separately, including separate channel maxima. Unit-suffixed nmcli frequencies parse correctly. AP density is explicitly distinct from client counts, measured utilization and interference.
- Successful delegated host observations are saved as unique private JSON files under .security-results/observations. observation_path and map_hint tell the caller how to reuse them. Save failures preserve observations and report observation_save_error.
- The existing map tool accepts input_paths, combines observation categories and deduplicates discovery-page hosts by address. Existing data/input_path callers still work. Paths stay confined to the Security workspace.
- Prompt guidance requests specific limited searches, reuse of observation paths, meaningful retries, explicit wireless units, actual tool calls for remaining work, and a visible final report.
- The runtime verifier imports Pi's ESM entry directly instead of CommonJS require.resolve. A --sdk-only check runs during the Docker build and checks pinned versions and required SDK exports.

Validation: 53 gateway tests and seven configuration migration tests passed. Stock Pi 1.0 native tests passed 18 intent queries, 132 canonical names and Web UI settings replay. The corrected verifier passed against actual Pi 1.0/Web UI 0.97 packages arranged in the container dependency layout. Catalog validation passed.

Limits: no Docker daemon or target Ollama/laptop was available here. The agent loop stays stock. Prompt guidance and simpler map inputs address the observed stopping trigger but cannot guarantee that a local model never ends with reasoning only; a live replay is needed. The artifact transport test mocks HTTP after this environment's Node runtime aborted on a Unix-socket fixture. It exercises persistence and rendering without real scans or packet capture.

Install the complete bundle as usual. Deployment refreshes the host helper, rebuilds services, updates both prompts/configuration, and rebuilds Pi. Start a new conversation. Generated observation files contain network inventory and can be removed after their maps are complete. No automatic retention cleanup is applied.

Commit subjects:
- Gateway: fix(recon): preserve partial topology and reuse saved map observations
- Pi: fix(runtime): verify ESM SDK imports and guide recon completion
