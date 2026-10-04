# Security CLI suite — 2026-10-01

The security MCP now exposes **58 tools**, discovered through Pi's native deferred MCP/tool_search path. The full Security catalog stays outside Pi's
standing prompt. The new CLI dependencies are installed during image build.

## What is available

| CLI | MCP capability | Output / execution behavior |
|---|---|---|
| Nmap | Existing discovery, port scan, service detection | `-oG -`, parsed before output limiting |
| Firecrawl | `firecrawl_scrape`, `firecrawl_map` | Clean Markdown / bounded JSON URL map |
| FFuF | `web_content_discover` | `-json`, noninteractive, HTTP 200 by default; configurable status codes |
| Subfinder | `subdomain_enum` | Passive JSONL enumeration; Subfinder is the selected Subfinder/Amass alternative |
| Searchsploit | `exploit_search`, `exploit_source` | Local Exploit-DB JSON search and paginated source inspection |
| sqlmap | `sqlmap` | Always `--batch`; detection, current database or database-name enumeration |
| Metasploit | `metasploit_info`, `metasploit_run` | Generated `.rc` files; info/options, check or explicit run |
| Netcat / Socat | `listener_start` | Asynchronous TCP listeners on container ports 4444–4453 |
| jq | `jq` | Streaming JSON/JSONL filtering with a result limit |
| Tshark | `pcap_analyze` with summary/conversations/fields views | `-T fields -e` extraction with display filters |
| Suricata | `suricata_test_rules` plus existing replay | `-T` validation, custom `-S` rules, PCAP replay, alert counts and packet hit rate |
| Osquery | `osquery` | One read-only SELECT/WITH query, JSON results |
| YARA | Existing `yara_scan` | Workspace custom rules; compilation/runtime errors reported correctly |
| Radare2 | `binary_analyze` | Scripted JSON metadata, imports, exports, strings, functions, disassembly |

`status` reports installation and Firecrawl configuration status.
`job_status`, `job_send`, and `job_stop` manage jobs.
FFuF filtering is performed directly on JSON records, equivalent to a jq status
filter, without an intermediate shell pipeline.


## Protocol-specific network tools

Fifteen bounded protocol tools complement generic host/port/service scanning:

| Protocol | MCP tools | Behavior |
|---|---|---|
| mDNS / DNS-SD | `mdns_discover` | Targeted UDP/5353 or multicast DNS-SD enumeration |
| UPnP / SSDP | `upnp_discover` | Targeted UDP/1900 or multicast device/service metadata |
| DHCP / DHCPv6 | `dhcp_discover`, `dhcp6_discover` | DHCPINFORM or bounded broadcast/multicast option discovery; no starvation |
| DNS | `dns_audit` | Recursion/DNSSEC/NSID/version checks; AXFR only when explicitly requested |
| SNMP | `snmp_discover`, `snmp_interfaces` | Read-only system/interface enumeration; no brute force or SET |
| SMB | `smb_audit`, `smb_shares` | Dialects/signing/OS metadata plus separate read-only share enumeration |
| NTP | `ntp_discover` | Time, stratum, reference and implementation metadata |
| LDAP | `ldap_discover` | Unauthenticated RootDSE capabilities/naming contexts |
| LLDP / CDP | `protocol_observe` with lldp/cdp | Passive bounded observation; packet-capture gate required |
| LLMNR / NBNS | `protocol_observe` with llmnr_nbns | Passive-only observation; never responds or poisons |
| WS-Discovery | `wsd_discover` | Targeted UDP/3702 or multicast Windows/printer/WCF discovery |
| ARP | `arp_discover` | Bounded IPv4 ARP host discovery on directly connected links |
| IPv6 NDP | `ndp_discover` | Read-only neighbor-cache inspection |

## High-level network reconnaissance

Five orchestration tools sit above the generic/protocol primitives:

| MCP tool | Purpose |
|---|---|
| `get_host_interface_info` | Host Ethernet/Wi-Fi state, IPs, gateway, link metadata and bounded Internet check |
| `perform_network_discovery` | Host discovery, OS/service/port enrichment, hostname resolution, SMB/NFS shares and common media services |
| `analyze_network_topology` | Subnets, VLANs, gateways, mDNS reflector evidence and opt-in peer/client-isolation checks |
| `analyze_wireless_environment` | Passive `iw`/`nmcli` Wi-Fi health/security/channel analysis; optional existing monitor-interface `airodump-ng` |
| `generate_graphical_network_map` | Confined Graphviz DOT/SVG/HTML output from aggregated recon JSON |

For correct laptop interface visibility while keeping the main security container isolated, run `scripts/install-security-host-recon-helper.sh`. The helper exposes only the four host-observation operations over `/run/mcp-security-host/recon.sock`; graphical map generation stays inside `mcp-security`. The Docker MCP mounts the socket read-only. If the helper is absent, host observation fails explicitly; container results never substitute for laptop observations. Full schemas, dependencies and permission details are in `docs/NETWORK-RECON-MCP.md`.

Targeted probes remain subject to `SECURITY_ALLOW_ACTIVE` and the existing target
allowlist. Broadcast/multicast/L2 operations intentionally stay inside the
`mcp-security` network namespace; their results include an explicit scope warning
because Docker bridge networking may not expose the host's physical LAN. No host
network mode, host PID namespace, `SYS_ADMIN`, or privileged-container mode is
introduced by this update.

## Build and verify

```bash
docker compose build mcp-security
docker compose up -d --no-deps --force-recreate mcp-security
docker compose exec -T mcp-security node /opt/mcp/smoke-security.mjs
node scripts/validate-catalog.mjs
node --test tests/security.test.mjs
```

The full image currently targets **amd64**, matching the ThinkPad AMD host. It
uses Rapid7's packaged Metasploit. This adds a substantial image layer: the
Metasploit package alone downloads roughly 408 MB and installs about 886 MB.

Firecrawl CLI 1.25.1, Subfinder 2.16.0 and Metasploit
6.5.3~20260818061200~1rapid7-1 have explicit build pins. Osquery 5.23.1 and
Radare2 6.1.8 have pinned release SHA-256 checksums in the installer. Subfinder's
download is checked against the release checksums. Rapid7 APT signatures are
verified with the vendored public key from its official omnibus installer.
Exploit-DB is snapshotted at build time; `/opt/exploitdb/SNAPSHOT_COMMIT` records
the commit. Debian packages follow the configured Debian repositories.

## Firecrawl configuration

Set these in the gateway's existing `.env`:

```dotenv
FIRECRAWL_API_URL=https://api.firecrawl.dev
FIRECRAWL_API_KEY=your-key-here
```

The hosted service performs the fetch remotely and uses your Firecrawl account.
For a self-hosted backend, set `FIRECRAWL_API_URL` to its reachable address and
configure a key if that backend requires one. The CLI is installed here; the
Firecrawl backend itself is not deployed by this update. Requests fail promptly
with a configuration message if the hosted key is missing. No interactive login
is attempted, and tool arguments never contain the key. Passive Subfinder
sources work without adding an account; some upstream sources need their own
provider configuration and may yield incomplete coverage.

## Workspace and visibility

Pi mounts `~/Projects` at `/workspace`. To let both containers see rules, logs,
PCAPs and binaries created by Pi, set the gateway's `MCP_WORKSPACE_PATH` to the
same **absolute host directory**, such as `/home/ron/Projects`, then recreate
`mcp-security` and `mcp-system`. An existing different workspace mapping is
preserved by the upgrade installer; align it before working on shared files.

Osquery, listeners and capture operate in the **security container's process
and network namespaces**. Osquery's `processes` and `listening_ports` tables do
not describe the host. Read-only `/host` files remain available to the dedicated
host tools. No host PID namespace or privileged-container mode is added.

`network_interfaces` has the same container-only visibility and must not
be used as LAN-host enumeration. For a laptop/LAN inventory, use `get_host_interface_info`, then
`perform_network_discovery` through the required host helper. Use `detail="hosts"`
for a quick host sweep, or default full enrichment. `port_scan` is a separate
targeted TCP check from the container.

## Active tools and jobs

The existing `SECURITY_ALLOW_ACTIVE`, `SECURITY_TARGET_ALLOWLIST`, and
`SECURITY_ALLOW_PUBLIC_TARGETS` settings govern active target checks, including
sqlmap and Metasploit. Public OSINT via Firecrawl/Subfinder is separate. These
are application checks, not a network sandbox: DNS can change after checking,
and third-party modules/backends can make auxiliary network requests.

Metasploit accepts one module under `auxiliary/scanner/` or `exploit/`, one
target, and console-safe option values. It defaults to `check`; `action: "run"`
launches it. It is a one-shot resource run ending with `exit -y`, so sessions
owned by that console end when it exits. It does not offer arbitrary resource
files, Ruby or console command strings. The sqlmap wrapper exposes testing and
database-name enumeration; raw CLI modes remain inside the image.

Listeners return immediately with a job ID so another MCP operation can run.
Use status with `next_offset` to read new output, send bounded input when needed,
and stop the job when finished. Both engines accept one connection; no local
shell is attached automatically. Listener jobs default to 120 seconds and allow
up to 300 seconds. Metasploit jobs have the same maximum. At most two background
jobs run concurrently. Deadlines and explicit stop kill their process groups.
Jobs and output buffers are transient across container restart.

Host callback ports are published on loopback by default:

```dotenv
SECURITY_LISTENER_BIND=127.0.0.1
```

For callbacks from an authorized LAN lab target, set this to the host's specific
LAN IPv4 address and recreate `mcp-security`. Use that host address and one of
4444–4453 for the callback; `127.0.0.1` within a container is that container.

Tool responses fit a 10 KB JSON envelope. Larger reports are saved under
`.security-results/` in the shared workspace, with a preview and full-file path.
Job output uses byte offsets and a 256 KB ring buffer; dropped bytes are reported.
Do not treat partial, time-limited or paginated output as an exhaustive result.

## Example Pi prompts

- “Check which security tools are installed using MCP; do not scan any targets.”
- “Filter `logs/eve.json` to show the first 20 alert signatures and source IPs.”
- “Validate `rules/lab.rules` and test it against `captures/lab.pcap`; report the packet hit rate.”
- “Inspect `samples/program.bin` with Radare2 and summarize its imports without executing it.”
- “Use passive Subfinder enumeration for my domain; identify any source errors.”

## Sources used for implementation

- [Firecrawl CLI](https://github.com/firecrawl/cli)
- [Subfinder CLI](https://docs.projectdiscovery.io/opensource/subfinder/usage)
- [Searchsploit manual](https://www.exploit-db.com/searchsploit)
- [sqlmap usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [Rapid7 omnibus installer](https://github.com/rapid7/metasploit-omnibus)
- [Osquery releases](https://github.com/osquery/osquery/releases/tag/5.23.1)
- [Radare2 release](https://github.com/radareorg/radare2/releases/tag/6.1.8)
