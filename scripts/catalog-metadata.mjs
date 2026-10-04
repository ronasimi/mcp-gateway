const META_KEY = 'ai.catalog';

export const SERVER_CATALOG = Object.freeze({
  system: {
    domain: 'system',
    description: 'Host, Docker, network administration, OpenWrt, image, document, and local briefing capabilities.',
  },
  security: {
    domain: 'security',
    description: 'Authorized security assessment, network reconnaissance, protocol inspection, hardening, vulnerability analysis, malware/IOC, PCAP, IDS, and incident-response capabilities.',
  },
  google: {
    domain: 'google',
    description: 'Authenticated Gmail, Google Calendar, and Google Drive capabilities with server-side credentials.',
  },
});

// Metadata is intentionally concise. Pi's deferred tool_search indexes names,
// descriptions, and schema guidance; aliases below are appended to descriptions
// only where wording overlap previously caused wrong-tool selection.
export const TOOL_CATALOG = Object.freeze({
  local_daily_briefing: {
    aliases: ['local daily briefing', 'London Ontario weather', 'CBC London news', 'morning weather and headlines'],
    scope: 'London Ontario current weather, seven-day forecast, and CBC London headlines in one Markdown card.',
    preferredFor: 'a local London Ontario weather/news briefing',
  },
  // Security network reconnaissance: clearly separate host state, live-host sweep,
  // comprehensive enrichment, topology, wireless, and rendering.
  get_host_interface_info: {
    aliases: ['host network state', 'active interface', 'IP gateway DNS', 'link speed', 'wifi association'],
    scope: 'Physical host interface state only; establishes local CIDRs and connectivity before LAN reconnaissance.',
    overlapGroup: 'network-recon',
    preferredFor: 'host interface, address, route, gateway, DNS, link, and Internet state',
  },
  security_network_interfaces: {
    aliases: ['security container interfaces', 'container routes', 'mcp security namespace'],
    scope: 'Security-container namespace diagnostics only; represents container interfaces and routes.',
    overlapGroup: 'network-recon',
    preferredFor: 'diagnosing the mcp-security container network namespace',
  },
  security_network_discover: {
    aliases: ['live host sweep', 'ping sweep', 'LAN host discovery', 'reachable IPs'],
    scope: 'Narrow live-host discovery only. Returns reachable hosts and intentionally leaves enrichment to broader or follow-up tools.',
    overlapGroup: 'network-recon',
    preferredFor: 'fast reachability and live-host enumeration when ports, OS, shares, and media details are not requested',
  },
  perform_network_discovery: {
    aliases: ['comprehensive network discovery', 'host enumeration', 'network inventory', 'LAN reconnaissance', 'service enumeration', 'OS fingerprinting', 'shares media discovery'],
    scope: 'Comprehensive LAN inventory: discovery plus names, MAC/vendor, OS, ports/services, shares, and common media services.',
    overlapGroup: 'network-recon',
    preferredFor: 'multi-host network reconnaissance or any request combining discovery with host/service enrichment',
  },
  security_port_scan: {
    aliases: ['open ports', 'TCP port scan', 'attack surface ports'],
    scope: 'One authorized target; identifies open TCP ports without broad multi-host enrichment.',
    overlapGroup: 'host-enumeration',
    preferredFor: 'open-port questions for a specific host',
  },
  security_service_detect: {
    aliases: ['service fingerprint', 'service versions', 'version detection'],
    scope: 'One authorized target; identifies products and versions on selected TCP ports.',
    overlapGroup: 'host-enumeration',
    preferredFor: 'service/version fingerprinting after ports are known',
  },
  analyze_network_topology: {
    aliases: ['network topology', 'routing relationships', 'VLAN analysis', 'LLDP CDP', 'client isolation', 'mDNS reflector'],
    scope: 'Topology and segmentation evidence from host routes, VLANs, discovery protocols, and optional peer observations.',
    overlapGroup: 'network-recon',
    preferredFor: 'subnets, routes, gateways, VLANs, LLDP/CDP, reflection, and client-isolation analysis',
  },
  analyze_wireless_environment: {
    aliases: ['wireless assessment', 'passive wireless assessment', 'wireless network assessment', 'wifi survey', 'spectrum survey', 'SSID BSSID channel', 'wifi security', 'channel congestion', 'signal RSSI'],
    scope: 'Passive Wi-Fi association, nearby BSSID/channel/security, signal, PHY/rate, congestion, and optional passive monitor observations.',
    overlapGroup: 'network-recon',
    preferredFor: 'dedicated Wi-Fi environment, channel, signal, and wireless-security assessment',
  },
  generate_graphical_network_map: {
    aliases: ['graphical network map', 'network diagram', 'SVG network map', 'HTML topology map'],
    scope: 'Rendering only; consumes structured reconnaissance data and produces SVG/HTML artifacts.',
    overlapGroup: 'network-recon',
    preferredFor: 'visual network maps after reconnaissance data exists',
  },

  // System networking: host/system diagnostics versus security reconnaissance.
  host_network_info: {
    aliases: ['host network info', 'host interfaces routes sockets'],
    scope: 'General host diagnostics for local interfaces/routes; use Security MCP for authorized reconnaissance and security assessment.',
    overlapGroup: 'system-network',
    preferredFor: 'local host diagnostics outside a security assessment',
  },
  network_interfaces: {
    aliases: ['system network interfaces', 'local interface addresses', 'local routes'],
    scope: 'System MCP local namespace/interface diagnostics; use dedicated OpenWrt or Security tools for routers and reconnaissance.',
    overlapGroup: 'system-network',
    preferredFor: 'system-side interface inspection',
  },
  network_scan_ports: {
    aliases: ['connectivity port scan', 'system port probe'],
    scope: 'General system/network diagnostic port probing; use Security MCP port scan for authorized security assessment.',
    overlapGroup: 'system-network',
    preferredFor: 'operational connectivity diagnostics rather than security reconnaissance',
  },
  openwrt_status: {
    aliases: ['router status', 'OpenWrt board uptime interfaces'],
    scope: 'Router health and board/network summary.',
    overlapGroup: 'openwrt',
    preferredFor: 'overall OpenWrt router status',
  },
  openwrt_wifi_status: {
    aliases: ['router wifi status', 'OpenWrt radios SSIDs channel signal'],
    scope: 'Router-side wireless radio and association state.',
    overlapGroup: 'openwrt',
    preferredFor: 'OpenWrt radio, SSID, channel, signal, and wireless association questions',
  },
  openwrt_clients: {
    aliases: ['router clients', 'DHCP leases', 'ARP neighbors', 'wifi stations'],
    scope: 'Router-side client inventory combining leases, neighbors, and Wi-Fi stations.',
    overlapGroup: 'openwrt',
    preferredFor: 'devices connected to an OpenWrt router',
  },

  // Documents/images: metadata versus content operations.
  document_info: {
    aliases: ['document metadata', 'PDF page count', 'document properties'],
    scope: 'Metadata and format inspection only.',
    overlapGroup: 'documents',
    preferredFor: 'type, size, page count, title, author, and format metadata',
  },
  document_extract_text: {
    aliases: ['read document text', 'extract PDF text', 'DOCX text'],
    scope: 'Content extraction for broad reading or summarization.',
    overlapGroup: 'documents',
    preferredFor: 'reading substantial document content',
  },
  document_search_text: {
    aliases: ['search inside document', 'find phrase in PDF', 'document grep'],
    scope: 'Targeted literal/regex search inside one document with bounded context.',
    overlapGroup: 'documents',
    preferredFor: 'finding a specific term, clause, name, heading, or error',
  },
  image_info: {
    aliases: ['image dimensions', 'image format', 'image properties'],
    scope: 'Pixel/format geometry and basic image properties.',
    overlapGroup: 'images',
    preferredFor: 'dimensions, format, color space, alpha, bit depth, and frame count',
  },
  image_metadata: {
    aliases: ['EXIF', 'camera metadata', 'GPS metadata', 'image timestamp'],
    scope: 'Embedded EXIF/XMP/ICC and camera/location metadata.',
    overlapGroup: 'images',
    preferredFor: 'camera, timestamp, GPS, orientation, and embedded metadata',
  },

  // Google: scalar/count tools versus record retrieval.
  gmail_get_unread_count: {
    aliases: ['unread email count', 'how many unread emails', 'unread inbox total'],
    scope: 'Exact scalar unread message/thread counts.',
    overlapGroup: 'gmail',
    preferredFor: 'count-only unread questions',
  },
  gmail_search_messages: {
    aliases: ['find email', 'search Gmail', 'list matching messages'],
    scope: 'Returns matching message records, metadata, and snippets.',
    overlapGroup: 'gmail',
    preferredFor: 'locating or listing messages rather than scalar counts',
  },
  calendar_list_events: {
    aliases: ['calendar agenda', 'upcoming meetings', 'calendar events'],
    scope: 'Returns event records over a time range.',
    overlapGroup: 'calendar',
    preferredFor: 'agenda and event lookup',
  },
  calendar_freebusy: {
    aliases: ['calendar availability', 'free busy', 'meeting conflicts'],
    scope: 'Returns busy intervals without loading full event records.',
    overlapGroup: 'calendar',
    preferredFor: 'availability and scheduling-window checks',
  },
  drive_search_files: {
    aliases: ['find Drive file', 'search Google Drive', 'locate document'],
    scope: 'Locates Drive files/folders and returns metadata.',
    overlapGroup: 'drive',
    preferredFor: 'finding file IDs and matching Drive items',
  },
  drive_read_text: {
    aliases: ['read Drive document', 'Drive file content', 'Google Docs text'],
    scope: 'Reads textual content from a known Drive file ID.',
    overlapGroup: 'drive',
    preferredFor: 'reading the content of a known textual Drive item',
  },
});

function cleanList(values) {
  return [...new Set((values || []).map((v) => String(v).trim()).filter(Boolean))];
}

export function decorateCatalogTools(tools, domain) {
  return tools.map((tool) => {
    const meta = TOOL_CATALOG[tool.name] || {};
    const aliases = cleanList(meta.aliases);
    const additions = [];
    if (meta.scope) additions.push(`Scope: ${meta.scope}`);
    if (meta.preferredFor) additions.push(`Best match: ${meta.preferredFor}.`);
    if (aliases.length) additions.push(`Search terms: ${aliases.join(', ')}.`);
    const description = additions.length ? `${tool.description} ${additions.join(' ')}` : tool.description;
    return {
      ...tool,
      description,
      _meta: {
        ...(tool._meta || {}),
        [META_KEY]: {
          domain,
          aliases,
          scope: meta.scope || tool.inputSchema?.description || tool.description,
          ...(meta.overlapGroup ? { overlapGroup: meta.overlapGroup } : {}),
          preferredFor: meta.preferredFor || tool.inputSchema?.description || tool.description,
        },
      },
    };
  });
}

export function catalogMetadataFor(name, domain) {
  const meta = TOOL_CATALOG[name] || {};
  return { domain, ...meta, aliases: cleanList(meta.aliases) };
}
