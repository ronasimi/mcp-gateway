# MCP catalog overlap map

The gateway keeps overlapping capabilities when they serve materially different scopes, and publishes `_meta["ai.catalog"]` metadata plus searchable scope/alias text so Pi's built-in deferred `tool_search` can distinguish them.

| Group | Tools | Distinction |
|---|---|---|
| Network recon | `get_host_interface_info`, `security_network_discover`, `perform_network_discovery`, `analyze_network_topology`, `analyze_wireless_environment`, `generate_graphical_network_map` | Host state → live-host sweep → comprehensive enrichment → topology → Wi-Fi survey → rendering. |
| Host enumeration | `security_port_scan`, `security_service_detect`, `perform_network_discovery` | Specific-host open ports → specific-host versions → multi-host enriched inventory. |
| System networking | `host_network_info`, `network_interfaces`, `network_scan_ports` | Local operational diagnostics; Security MCP owns security reconnaissance. |
| OpenWrt | `openwrt_status`, `openwrt_wifi_status`, `openwrt_clients` | Router health → radio/SSID state → attached-client inventory. |
| Documents | `document_info`, `document_extract_text`, `document_search_text` | Metadata → broad content extraction → targeted in-document search. |
| Images | `image_info`, `image_metadata` | Pixel/format properties → EXIF/XMP/camera/location metadata. |
| Gmail | `gmail_get_unread_count`, `gmail_search_messages` | Exact scalar count → matching message records. |
| Calendar | `calendar_list_events`, `calendar_freebusy` | Event details → availability intervals. |
| Drive | `drive_search_files`, `drive_read_text` | Locate file IDs → read content of a known file. |

The high-level Security reconnaissance tools intentionally remain separate because collapsing them would either over-scan simple requests or under-collect comprehensive assessments. The metadata makes the scope distinction explicit instead of relying on Pi-side orchestration rules.
