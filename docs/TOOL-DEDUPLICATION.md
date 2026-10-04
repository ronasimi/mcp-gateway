# Tool deduplication and search — 2026-10-03

This is a breaking catalog revision for the System, Security and Google MCP services (API version 2.0.0). Start a new Pi conversation after deployment so old active schemas and obsolete adapter instructions are replaced. Pi 1.0.0, its BM25 ranker, agent loop and native MCP implementation remain stock.

## Names and inventory

Security supplies its domain through the native namespace: `mcp__security__listener_start`, not `mcp__security__security_listener_start`. All former `security_` tool prefixes are removed. `security_tool_status` becomes `status`; `security_suricata_analyze_pcap` becomes `suricata_alerts`. Google’s `google_auth_status` becomes `auth_status`. Distinct service names such as `gmail_`, `calendar_`, `drive_`, `docker_`, `image_` and Playwright’s `browser_` remain meaningful.

| Service | Before | After | Status |
|---|---:|---:|---|
| System | 54 | 51 | Four entries removed; `openwrt_targets` added |
| Security | 65 | 58 | Seven redundant entries consolidated |
| Google | 23 | 23 | Names/metadata revised; binary download fixed |
| Playwright | 25 | 25 | Pinned upstream API retained; Pi hides `browser_close` by default |
| Memory | 9 | 9 | Pinned upstream API retained; no repeated namespace prefix |
| SearXNG | 3 | 3 | Official baseline API retained; deployed floating image can differ |
| Total | 179 | 169 | 168 searchable by default in Pi, before optional disabled services |

The 132 owned tools all have curated purpose descriptions and focused aliases. Third-party upstream tool descriptions remain intact; their configured namespace summaries are shortened. Their published names were audited for repeated service prefixes. Playwright `browser_close` is incompatible with the default shared browser context, so native `toolExposure` hides it; use `browser_tabs` with `action="close"`. A deployment using independent browser contexts may explicitly override that exposure.

## Consolidation map

Old Security names in this table include their original prefix. Retired names are not published as aliases or additional schemas.

| Previous entry | Canonical replacement | Preserved behavior / change |
|---|---|---|
| System `host_network_info` | Security `get_host_interface_info` | Actual laptop namespace through the required host helper |
| System `network_interfaces` | Security `get_host_interface_info` | Container interfaces no longer compete with host inventory |
| System `network_scan_ports` | Security `port_scan` | Authorized host/CIDR TCP scan; optional `service_detection=true` |
| Security `security_service_detect` | Security `port_scan` | `service_detection=true`; structured products/versions |
| Security `security_network_discover` | Security `perform_network_discovery` | `detail="hosts"` for host sweep; default full enrichment; host-helper scope |
| Security `security_dns_records` | System `network_dns_lookup` | `types=["A","AAAA","CNAME","MX","NS","TXT","SOA","CAA"]`; single `type` and PTR also supported |
| System `image_thumbnail` | System `image_resize` | `mode="thumbnail"`, width/height, default no enlargement; retains ImageMagick `-thumbnail` behavior |
| Security `security_lldp_observe` | Security `protocol_observe` | `protocol="lldp"`; same passive capture scope/gate |
| Security `security_cdp_observe` | Security `protocol_observe` | `protocol="cdp"` |
| Security `security_llmnr_nbns_observe` | Security `protocol_observe` | `protocol="llmnr_nbns"` |
| Security `security_pcap_summary` | Security `pcap_analyze` | `view="summary"` (default) |
| Security `security_pcap_conversations` | Security `pcap_analyze` | `view="conversations"` and selected protocol |
| Security `security_pcap_fields` | Security `pcap_analyze` | `view="fields"`, existing field/filter/limit arguments |

`port_scan` remains a targeted scan **from the Security container**. It is not relabeled as a host scan. Laptop/LAN inventory uses `perform_network_discovery`. Security `network_interfaces` remains explicitly container-scoped for packet-capture setup. System ping, HTTP timing and single-port connection checks remain useful diagnostics.

The native configuration merge rewrites existing Security/Google `toolExposure` names and consolidated selectors, preserving hidden restrictions and user credentials, URLs, timeouts, enabled states and additional servers. Existing callers must migrate names and any mode arguments above. DNS now returns `{name, records}` grouped by type; unified port scans return both per-host and flattened open-port records.

## Search changes

Stock Pi builds each search document from the tool name, description, schema and namespace description/instructions. The former Security namespace copied “reconnaissance”, “topology”, “wireless” and other unrelated terms into every Security tool. Short unrelated schemas then won BM25 ranking. The attached run’s first query reproduced that failure exactly.

Both namespace sources now contain service identity only. Each owned tool has a concise purpose statement, a small set of specific aliases and a short schema heading. The universal “Search terms” label was removed because it made the word “search” appear in every document. Router arguments consistently request configured aliases, discoverable through `openwrt_targets`.

| Exact run query | Top three before | Top three after |
|---|---|---|
| `security MCP tools for network reconnaissance and mapping` | `security_listener_start`, `security_tool_status`, `security_job_stop` | `get_host_interface_info`, `generate_graphical_network_map`, `perform_network_discovery` |

The positive prompt retains domain routing. It requests narrow discovery limits, retries mismatched searches with specific operations, starts laptop reconnaissance at `get_host_interface_info`, translates legacy adapter terminology into native calls, and ties device rows and file links to successful observations. This is guidance, not a replacement agent loop or a guarantee against model hallucinations.

## Other corrections

- Host observation fails explicitly if the helper is unavailable; deployment refreshes its installed source.
- Reconnaissance has one 240-second default / 300-second maximum scan budget, phase-level completeness and host-page offsets. It retains service version fields.
- Wireless observations default to cached passive data; active rescanning requires `rescan=true`. Channel width is reported when present.
- Host state includes resolver-file DNS and connected private physical subnets. VLAN interfaces remain excluded and are documented as unassessed.
- Maps reject empty evidence and label unknown physical links as logical relationships. Managed-mode AP peers are not treated as a list of LAN wireless clients.
- Drive download accepts binary files and preserves original bytes, including JSON whitespace; text-reading restrictions remain specific to `drive_read_text`.

## Validation and deployment

Run `node --test tests/*.test.mjs`, `python3 tests/config-merge-test.py`, and `node scripts/validate-catalog.mjs` from the gateway repository. The Pi repository’s `tests/native-mcp-smoke.mjs` uses the actual Pi 1.0 SDK and Web UI settings replay, including shipped namespace descriptions and server initialize instructions.

The complete bundle includes a source installer with backups and preservation of credentials, data, model overrides and existing MCP endpoints. Deployment rebuilds owned services, refreshes the host helper, merges native configuration and recreates Pi. Existing explicit request timeouts are preserved; custom shorter limits may interrupt recon before its own deadline.

See [RUN-REVIEW-2026-10-03.md](RUN-REVIEW-2026-10-03.md) for the attached run’s evidence and remaining live-model validation.
