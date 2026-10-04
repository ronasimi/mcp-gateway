# Laptop and LAN reconnaissance

The four observation tools use the required host helper over `/run/mcp-security-host/recon.sock`. The Security container fails explicitly when the helper is missing or broken. Rendering remains in the container so files land in the shared workspace.

Install or refresh the root-owned helper with `./scripts/install-security-host-recon-helper.sh`. The complete deployment script performs this step. On Arch, the helper installer reports any missing dependencies; `--install-deps` explicitly enables their installation. The service retains target allowlists, the active-probe gate and the packet-capture gate. It exposes no shell command endpoint.

| Tool | Purpose | Main arguments |
|---|---|---|
| `get_host_interface_info` | Physical Ethernet/Wi-Fi addresses, routes, gateway, resolver-file DNS, link speed and connectivity | Optional `interface`, `internet_check` |
| `perform_network_discovery` | Host inventory with optional enrichment | `cidrs`, `interface`, `detail`, `max_hosts`, `host_offset`, `port_profile`, `timeout_seconds` |
| `analyze_network_topology` | Physical subnets, routes, gateway, mDNS and optional LLDP/CDP/peer evidence | `interface`, `peer_targets`, `observe_mdns`, `observe_l2` |
| `analyze_wireless_environment` | Wi-Fi association, signal/rate/width, cached BSSIDs and channel overlap | `interface`, `rescan`, `use_airodump`, `monitor_interface` |
| `generate_graphical_network_map` | DOT/SVG/self-contained HTML from collected observations | `data` or `input_path`, `output_base`, `format` |

Use native Pi `tool_search` with the operation name, then call the exact returned `mcp__security__...` tool. The shipped prompt includes this workflow. Older adapter instructions using `mcp_search`/`mcp_call` are obsolete.

## Visibility and evidence

Physical interfaces require Wi-Fi evidence or sysfs hardware-device backing. Docker bridges, veth, VPN/tunnel interfaces, bonds and VLAN interfaces remain excluded. VLAN absence is therefore **not established** by an empty VLAN list. DNS describes `/etc/resolv.conf`; a local resolver stub is not proof of the upstream DNS server. Run interface-specific discovery for each intended physical connection.

Automatic discovery infers the selected physical interface’s IPv4 ranges. Larger-than-/20 inferred ranges are clamped to the local /24. Explicit CIDRs must be authorized IPv4 /20–/32 ranges. IPv6 addresses are reported, but this inventory scanner remains IPv4.

`detail="hosts"` performs a host sweep only. `detail="full"` adds bounded service/OS detection, names, shares and media probes as selected. Nmap version fields remain in the structured output; service banners alone do not establish an operating system.

The **total** scan/enrichment budget defaults to 240 seconds and is capped at 300, below Pi’s shipped 330-second request timeout. Each phase consumes the remaining budget. `phases` reports failures or skipped work; partial scans have `complete=false` and retain usable observations. For slow environments use fewer hosts, /32 target CIDRs, or narrower optional phases.

`max_hosts` limits each page. Use `next_offset` as the next `host_offset` with the same arguments. Hosts are sorted by address; `page_complete` describes the returned page and `complete` also requires that no page remains. Each page rediscovers live hosts, so membership can change between pages; retain and deduplicate observed addresses.

Wi-Fi defaults to `nmcli --rescan no`, with `iw scan dump` for cached fallback. `rescan=true` explicitly requests active scanning. Optional airodump observation requires an existing monitor interface and the capture gate; it never enables monitor mode. Cached data can be stale. Channel overlap is evidence of potential contention, not a measured spectrum-utilization percentage.

Topology observations label uncertain isolation/reflection findings. Map generation requires collected host/interface/subnet data. Dotted edges show logical reachability with unknown physical attachment; dashed edges require observed Wi-Fi association. The tool returns actual output paths after successful rendering. HTML is a self-contained SVG document, not an interactive topology editor.

Targeted protocol checks, `port_scan`, `network_interfaces`, osquery and packet capture retain their explicit **container** scope. OpenWrt tools inspect a separate, configured SSH target; use `openwrt_targets` to find real aliases.
