# mDNS subnet leads

`discover_mdns_subnets` runs in the host helper on an eligible physical interface. It sends bounded DNS-SD queries, follows returned PTR/SRV names and collects advertised A, AAAA and TXT records. It uses Node UDP sockets directly; a running Avahi daemon or D-Bus service is not required. DNS-SD enumeration plus common service queries help discover devices that do not answer enumeration.

Search the exact operation with Pi `tool_search` and `limit: 1`, then call the returned `mcp__security__discover_mdns_subnets` with `{}` or the returned host interface name. Optional duration is 3–30 seconds; record count is bounded to 512. Responses are saved as observation artifacts. The endpoint observes advertised addresses only: it does not scan hosts, create routes, change router settings, or authorize scans.

For every address, the result separates the advertised record, its source, its relation to the selected interface's known subnets, and any candidate grouping. Each candidate includes CIDR, prefix length, range_start, range_end and address_count. These are inclusive mathematical address ranges, not promises that every address is usable or reachable.

- `local_interface`: the prefix is known from a physical interface address.
- `known_route`: the prefix is routing coverage. A /16 aggregate or /32 host route does not establish the actual remote subnet mask.
- `heuristic`: private IPv4 defaults to /24 grouping and IPv6 ULA defaults to /64. Both are configurable hypotheses; mDNS carries no subnet mask.
- Public addresses are retained without heuristic scan ranges. Link-local, loopback and multicast addresses do not establish remote subnet candidates.

Outside-subnet advertisements are possible reflection evidence. Multihoming, stale advertisements and proxy registrations remain alternatives. `reflector_confirmed` stays false. The socket joins the IPv4 mDNS multicast group on the selected interface; Node does not expose incoming interface metadata, so advertisements are host observations rather than packet-level proof of cross-interface forwarding. AAAA records can arrive over IPv4; IPv6-only multicast and devices that do not advertise are not covered.

Topology mDNS browsing now uses the same direct collector. Unavailable transport retains its actual diagnostics, a successful empty observation is distinct from failure, and incomplete collection leaves topology partial. This does not relax physical-interface restrictions or existing scan authorization.

## Deployment

Apply the supplied update to the gateway and Pi repositories. Reinstall the host helper with `bash scripts/install-security-host-recon-helper.sh`, then rebuild/recreate `mcp-security` using Docker Compose. The installer copies `mdns-subnets.mjs` alongside the helper. Both pieces must be updated: the container exposes the new schema and the helper executes it. Start a new Pi chat to refresh discovery and skill instructions.

## Validation

Gateway tests: 73 passed, one environment-dependent UID-switch test skipped. Native Pi SDK: all 138 owned tools connected, 24 intent queries and exact-name lookup passed. Unit fixtures cover A/AAAA/PTR/SRV parsing, malformed DNS/compression loops, TTL-zero withdrawals, socket errors, IPv4 /23 and IPv6 range arithmetic, local/route/heuristic distinctions, and absence of automatic scanning. Live laptop multicast delivery remains to be tested after installation.
