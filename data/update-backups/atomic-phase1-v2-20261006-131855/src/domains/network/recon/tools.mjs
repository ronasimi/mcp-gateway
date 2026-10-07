import { stringSchema as str, integerSchema as integer, booleanSchema as bool, arraySchema as arr, openObjectSchema as anyObject, toolSchema as tool } from '../../../core/schema.mjs';

const iface = str('Optional host network interface. Omit to auto-select; reuse selected_interface.', { maxLength:64 });
const cidr = str('Authorized private/allowlisted IPv4 CIDR such as 192.168.1.0/24.', { maxLength:64 });

export const NETWORK_RECON_TOOLS = [
  tool('discover_mdns_subnets',
    'Browse DNS-SD on the laptop physical interface using direct mDNS UDP queries. Returns a compact model-facing report_hosts/report_candidate_networks projection while saving full raw DNS audit evidence at observation_path and a compact recovery artifact at report_path. DNS-advertised A/AAAA addresses remain separate from UDP packet_source_addresses and service instances are joined through exact SRV targets. Identifies advertised addresses outside local subnets and groups candidate networks with address ranges. Local prefixes are confirmed; routes describe routing coverage; /24 and /64 fallbacks are explicit hypotheses. If status is unavailable, empty evidence arrays mean collection did not occur and are not proof that hosts, candidate ranges, or reflection are absent. Never scans inferred ranges or confirms a reflector.',
    {interface:iface, duration_seconds:integer('Observation window; default 8, maximum 30 seconds.',3,30), max_records:integer('Maximum advertised records; default 256.',16,512), max_queries:integer('Maximum unique DNS-SD follow-up queries; default 96, maximum 256. Reaching the cap marks coverage partial.',16,256), ipv4_candidate_prefix:integer('Fallback IPv4 grouping prefix; default 24. Not an observed mask.',20,32), ipv6_candidate_prefix:integer('Fallback IPv6 grouping prefix; default 64. Not an observed mask.',48,128)}),
  tool('get_host_interface_info',
    'Host network-state inventory for a laptop connected to a new Ethernet or Wi-Fi network. Only physical Ethernet/Wi-Fi interfaces are eligible; Docker bridges, veth pairs, VPN/tunnel devices, VLANs and other virtual interfaces are excluded. Reports active/default interfaces, wired vs wireless type, IPv4/IPv6 addresses, routes/default gateway, link speed, Wi-Fi association metadata when available, and a bounded external-connectivity check. Host visibility requires the security host-recon helper; an unavailable helper produces an error.',
    { interface:iface, internet_check:bool('Check default-route, DNS-resolution, and one ICMP reachability probe to a fixed public resolver; default true.') }),
  tool('perform_network_discovery',
    'Comprehensive authorized local-network discovery. Automatic interface/CIDR selection is restricted to physical Ethernet/Wi-Fi interfaces; virtual interfaces and their routes are ignored. Discovers live hosts, resolves names from Nmap/reverse DNS/mDNS/locally visible DHCP leases, fingerprints operating systems, scans ports/services, and identifies SMB/NFS shares and common DLNA/Plex/Jellyfin/Emby media services. CIDRs may be supplied or inferred from the selected host interface. Large inferred networks are clamped to the local /24 unless explicitly supplied.',
    {
      cidrs:arr('One to four authorized IPv4 CIDRs. Omit to infer directly connected networks from the active interface.',cidr,{maxItems:4}),
      interface:iface,
      detail:str('Inventory depth; hosts discovers reachable addresses only, full also enriches names, OS, ports and services. Default full.',{enum:['hosts','full']}),
      host_offset:integer('Live-host page offset returned as next_offset; default 0.',0,65535),
      max_hosts:integer('Maximum live hosts to enrich; default 64, maximum 128.',1,128),
      port_profile:str('Port coverage: quick=top 100, standard=top 1000 plus common share/media ports, full=all TCP ports. Full is limited to at most 16 hosts.',{enum:['quick','standard','full']}),
      os_detection:bool('Attempt Nmap OS fingerprinting; default true. Requires raw-packet privileges.'),
      resolve_names:bool('Resolve names using DHCP lease files, reverse DNS, and mDNS where available; default true.'),
      include_shares:bool('Enumerate SMB/NFS shares read-only when their services are detected; default true.'),
      include_media:bool('Probe common UPnP/DLNA/Plex/Jellyfin/Emby ports and metadata; default true.'),
      timeout_seconds:integer('Total call budget across all scan and enrichment phases; default 240, maximum 300 seconds.',30,300)
    }),
  tool('analyze_network_topology',
    'Analyze local network structure and behavior using physical Ethernet/Wi-Fi interfaces only; virtual interface routes are excluded from active probing. Reports connected physical subnets, gateways, mDNS service visibility and possible reflection across subnets. Optionally tests specified same-subnet peers for possible Wi-Fi client isolation using bounded ICMP/ARP discovery; it does not spoof or poison traffic.',
    {
      interface:iface,
      peer_targets:arr('Known authorized peer IPs expected to be on the same local network. Supplying peers enables the client-isolation test.',str('Authorized peer IPv4 address.'),{maxItems:16}),
      observe_mdns:bool('Browse mDNS/DNS-SD services for topology hints; default true.'),
      observe_l2:bool('Passively observe LLDP/CDP for topology hints; default false and requires SECURITY_ALLOW_PACKET_CAPTURE=true.'),
      timeout_seconds:integer('Observation/probe duration per bounded operation; default 8, maximum 30.',3,30)
    }),
  tool('analyze_wireless_environment',
    'Passive Wi-Fi health/security/congestion analysis using iw and nmcli, with optional airodump-ng collection from an already-existing monitor-mode interface. Reports current association, signal, bitrate/PHY hints, nearby BSSIDs/channels/security, channel congestion/overlap, and visible station data where the driver/interface mode exposes it. Never enables monitor mode, deauthenticates clients, captures credentials, or injects frames.',
    {
      interface:iface,
      rescan:{type:'boolean',enum:[false],description:'Passive-only tool: omit or use false. Active rescans are rejected.'},
      use_airodump:bool('Also collect passive airodump-ng observations; default false. Requires monitor_interface and SECURITY_ALLOW_PACKET_CAPTURE=true.'),
      monitor_interface:iface,
      duration_seconds:integer('airodump passive observation duration; default 10, maximum 30.',3,30)
    }),
  tool('generate_graphical_network_map',
    'Generate Graphviz DOT/SVG and optional self-contained HTML with zoom controls from aggregated network-recon JSON. The map distinguishes known wired/wireless links, shows gateway/Internet relationships, link speed when known, and annotates hosts with hostname, OS, open ports, shares, and media services. Provide either data directly or a workspace JSON input_path.',
    {
      data:anyObject('Aggregated object containing outputs from get_host_interface_info, perform_network_discovery, analyze_network_topology and/or analyze_wireless_environment.'),
      input_path:str('Workspace-relative JSON file containing aggregated network data.'),
      input_paths:arr('Nonempty observation artifact paths returned by successful saves; omit data and input_path when using this field; merges their data without copying JSON. Include host, topology and wireless observation paths plus every discovery page from this workflow; inspect missing_observations in the result.',str('Security workspace observation JSON path.'),{minItems:1,maxItems:128}),
      output_base:str('Output basename without extension, stored under .security-results. Relative names are prefixed automatically; default .security-results/network-map. Absolute paths and traversal are rejected.',{maxLength:240}),
      format:str('Map output format.',{enum:['svg','html','both']}),
      title:str('Optional map title; maximum 120 characters.',{maxLength:120})
    })
];

export const NETWORK_RECON_TOOL_NAMES = new Set(NETWORK_RECON_TOOLS.map(t => t.name));
// Only host-observation tools need the laptop's real network namespace. Map rendering
// intentionally stays inside mcp-security so outputs land in the normal shared workspace.
export const NETWORK_RECON_HOST_TOOL_NAMES = new Set([
  'discover_mdns_subnets',
  'get_host_interface_info',
  'perform_network_discovery',
  'analyze_network_topology',
  'analyze_wireless_environment'
]);
export const NETWORK_RECON_ACTIVE_TOOL_NAMES = new Set(['discover_mdns_subnets','perform_network_discovery','analyze_network_topology','analyze_wireless_environment']);
export const NETWORK_RECON_WORKSPACE_WRITES = new Set(['generate_graphical_network_map']);
