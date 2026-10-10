# Physical-network observations

## Host helper

Security remains on Docker's bridge. Physical Ethernet/Wi-Fi operations delegate to a bounded root-owned host service over `/run/mcp-security-host/recon.sock`:

```bash
bash scripts/install-security-host-recon-helper.sh
```

On Arch, `--install-deps` explicitly allows installation of missing packages. Refresh the helper after source or gate changes. Its installer copies the shared modules and restarts updated code. It exposes bounded operations, not a general shell.

```bash
systemctl status mcp-security-host-recon
journalctl -u mcp-security-host-recon -n 100 --no-pager
```

The helper stores observations in its private state workspace and the gateway writes delegated result artifacts into the shared MCP workspace. Rendering remains inside the Security container.

## Tool families

| Tool | Observation or operation |
| :--- | :--- |
| `get_host_interface_info` | Physical interfaces, addresses, routes, gateway and link facts |
| `perform_network_discovery` | Authorized host inventory with bounded optional enrichment |
| `analyze_network_topology` | Routes, physical prefixes and selected topology evidence |
| `analyze_wireless_environment` | Association, signal/rate/width and cached neighboring BSSIDs |
| `discover_mdns_subnets` | Advertised addresses and candidate ranges through bounded DNS-SD queries |
| `observe_broadcast_multicast` | Passive ARP, mDNS, LLMNR and SSDP observations |
| `probe_gateway_proxy_arp` | Explicit bounded ARP probe and responder-MAC comparisons |
| `probe_gateway_hairpin` | Explicit peer path comparison |
| `observe_dns_cache` | Explicit nonrecursive DNS cache observations |
| `generate_graphical_network_map` | DOT, SVG and self-contained HTML from collected observations |

Discover one exact operation through Pi `tool_search`, inspect its schema, then use `tool_invoke`. High-level host operations fail closed when the helper is unavailable. Generic `network_interfaces`, protocol probes and scanner operations retain their documented container scope.

## Bounds and interpretation

Physical interface selection requires Wi-Fi evidence or sysfs device backing. Docker links, VPN/tunnels, bonds and VLANs are excluded; exclusion is not evidence that a VLAN or tunnel is absent on the host.

Discovery accepts authorized IPv4 ranges. Inferred ranges larger than /20 are narrowed to the local /24; explicit ranges are /20–/32. `detail="hosts"` performs a sweep without service/share/media enrichment. The shared execution deadline is at most 300 seconds. Partial phases remain explicit. Use returned `next_offset` as `host_offset`; each page can rediscover changing hosts.

Wireless observation defaults to cached results. `rescan=true` requests active scanning. Optional airodump requires an existing monitor interface and the capture gate; the helper never enables monitor mode. Cached channel overlap is not measured spectrum utilization.

Passive multicast observation is bounded by duration, matching packet count and evidence-row count. Active ARP, SSDP and DNS-SD follow-ups require their applicable runtime gates and explicit user consent. Passive-only requests must remain passive.

One advertised address or shared MAC cannot prove client isolation, reflection or hairpin routing. Keep scope, packet/probe counts, provenance, completeness and untested phases in the report. A timeout or unavailable collector is distinct from a successful empty observation.

## mDNS candidate ranges

mDNS has no subnet mask. Candidate ranges use the following evidence:

| Basis | Meaning |
| :--- | :--- |
| `local_interface` | Actual local physical-interface prefix |
| `known_route` | Route-covered candidate range; remote mask unconfirmed |
| `heuristic` | Grouped address hypothesis; mask unknown |

Inference uses advertised A/AAAA records, not UDP source addresses. The bounded collector joins PTR/SRV/TXT records, follows DNS-SD names and marks query-limit coverage as partial. Outside-subnet advertisements can suggest reflection; multihoming, stale records and proxy registrations remain alternatives. `reflector_confirmed` stays false.

Use the returned `host_table_markdown` and `candidate_table_markdown` for exact reporting. Keep complete hostname/IP strings and string-valued IPv6 range counts. Only a `local_interface` range may be called a confirmed local prefix.

## Saved evidence and maps

Full raw evidence and compact recovery reports are separate artifacts. When a response is truncated, recover `report_path` first. Use `read_security_result` for selected fields under `.security-results`; its schema bounds pagination and rejects traversal, symlinks and prototype selectors. Retrieval is not a fresh network operation.

Maps require observed data or saved input paths. Unknown physical attachment stays visibly uncertain; logical reachability does not prove a physical link. HTML is a self-contained SVG view. Download the returned actual artifact paths rather than treating opaque Pi result references as filenames.

## Passive observation metadata

`observe_broadcast_multicast` publishes `x-pi-effect: passive_capture`, `readOnlyHint: false` because it saves an observation artifact, and `idempotentHint: false` because later captures observe new traffic. It is not in the active-tool set. ARP, hairpin and DNS-cache probe operations remain `active_probe`. The startup verifier checks these public catalog declarations without executing probes.

## Masscan

Discover `security masscan scan`, then invoke the exact returned `mcp__security__masscan_scan` through `tool_invoke`. Both `masscan` and the common `massscan` spelling identify this scanner; discovery does not substitute Nmap or passive capture. The public effect is `active_probe`, with non-idempotent annotations to keep subsequent requested scans fresh.

Example arguments after explicitly authorizing the target scan and enabling Pi's runtime opt-in:

```json
{"target":"192.168.1.10","ports":"22,80,443","rate_limit":100,"timeout_seconds":60}
```

This is an illustrative target; use the actual authorized address. The tool takes one literal IPv4 address or CIDR, never a hostname or IPv6 target. CIDRs are normalized and checked against the gateway target allowlist in their entirety. `interface`, when supplied, must be a Security-container interface, not a host-helper interface.

| Bound | Value |
| :--- | :--- |
| Addresses | At most 4,096, `/20` or narrower |
| TCP ports | Required; at most 1,024 distinct ports |
| Host/port probes | At most 262,144 per call |
| Packet rate | Default 100; maximum 1,000 packets/second |
| Process deadline | Default 60; maximum 180 seconds |
| Receive wait | 5 seconds; accounted for in the deadline |
| Retries | 0 |
| Captured subprocess output | 1 MiB; overflow stops the process and marks results incomplete |

Scope/rate combinations that cannot fit within the selected deadline are rejected before execution. No arbitrary CLI flags, source spoofing, banner collection, config paths or shell commands are exposed. An ambient `/etc/masscan/masscan.conf` containing options is rejected; the clean image removes that implicit configuration.

Target address, requested port and planned probe counts describe the requested scope, not measured packets sent. The scanner emits list-format observations. The gateway parses and deduplicates them, rejects unexpected addresses/ports/protocols, and reports timeouts, output caps and parse problems as incomplete evidence. Large results are stored under `.security-results` and retrieved with `read_security_result`. A successful process with no returned ports does not prove that the ports are closed. Use Nmap `port_scan` for service/version detection.

This tool runs inside the existing Security-container namespace with `NET_RAW`; no host-network mode, extra host-helper privilege or firewall change is introduced. Reachability and return traffic depend on your deployment. Physical-interface and isolation claims still need the host-helper observations.

Upstream references: [Masscan usage/output](https://github.com/robertdavidgraham/masscan), [Masscan manual](https://github.com/robertdavidgraham/masscan/blob/master/doc/masscan.8.markdown), [pinned Debian Bookworm package](https://packages.debian.org/bookworm/masscan).
