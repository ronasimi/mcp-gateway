# Review of the attached reconnaissance run

Source: `2026-10-03T17-33-15-916Z_01a102d3-c70c-7580-b98e-eb79fe381ba7.jsonl`. Model: `gemma-4-e2b-qat-32k-security:latest`. The session spent about **8 minutes 31 seconds** between the user request and final response. No actual LAN inventory or map generation completed.

| Time (UTC) | Observed action | Result |
|---|---|---|
| 17:34:24 | `tool_search`: “security MCP tools for network reconnaissance and mapping” | Eight largely unrelated tools loaded, led by listener/job/status operations |
| 17:35:51 | Bash: `ip a && ip route && ss -tuln` | Failed: `ip` was unavailable in the Pi container |
| 17:36:42 | Security backend status | Reported installed binaries and a configured/available host-helper socket |
| 17:37:37 | System OpenWrt clients with `target="default"` | Failed SSH hostname resolution; the target was invented |
| 17:41:51 | Final response | Claimed a completed assessment with invented addresses, devices, ports, Wi-Fi measurements and map paths |

The model made four tool calls total: one search, one Bash command, one backend-status call and one router call. It never invoked the host interface, comprehensive discovery, topology, wireless or graphical-map capabilities. The backend-status response does not constitute LAN evidence. No successful tool output supports the final device table or its claimed output files.

## Causes and changes

1. **Search metadata polluted every tool document.** The broad Security namespace descriptions applied reconnaissance terms to unrelated tools. The old and new rankings were reproduced offline with Pi’s unmodified BM25 implementation. The new first result is host interface inspection; the next two are map rendering and full network discovery.
2. **Recovery stopped after wrong-tool failures.** The prompt now directs operation-specific re-search and gives the staged host-helper route. It identifies Bash’s Pi-container scope and provides `openwrt_targets` to discover configured router aliases.
3. **The request used the retired adapter interface.** The user prompt named `mcp_search` and `mcp_call`, whereas this runtime offers `tool_search` followed by direct native MCP calls. The shipped prompt explicitly explains the translation.
4. **The final answer ignored its lack of evidence.** Positive guidance now requires each device row, measurement and generated-file link to trace to a successful tool result, and marks dependent results unavailable after failures. No custom model-output validator or agent-loop patch was added.

Source review also found and corrected total recon time budgeting, host pagination, passive wireless defaults, misleading map edges and Drive binary downloading. These were latent defects; the attached run did not reach those operations.

## Verification boundaries

Offline tests verify schemas, naming, dispatch, target controls, merged modes, stock search rankings, Web UI settings replay and preservation during migration. Network tools use fixture executables or injected command runners in tests; no targets were scanned. The exact original model run has not been replayed against your laptop/Ollama environment. Improved retrieval does not prove that Gemma will complete the full workflow or stop fabricating results; a fresh live session is the remaining check.

## Updated test prompt

> I am authorized to assess the private networks connected to this laptop. Use native `tool_search` and the exact returned MCP tools. Begin with host interface information, then complete host discovery/enrichment, topology, passive wireless observations and map generation from the collected data. Reuse results, follow returned host-page offsets and report incomplete scan phases. Use actual observed devices and returned file paths. For unavailable steps, report the concrete failure and mark dependent fields unavailable. Finish with a concise device table, topology/wireless findings and the generated map paths.
