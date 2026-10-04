# Remaining purposeful overlap

Exact wrappers have been consolidated; the full migration table is in [TOOL-DEDUPLICATION.md](TOOL-DEDUPLICATION.md).

| Tools | Reason to retain separate capabilities |
|---|---|
| `get_host_interface_info`, `perform_network_discovery`, topology, wireless, map | Host state, collection, interpretation, radio observations and rendering are distinct stages. |
| `port_scan`, `perform_network_discovery`, `network_port_check` | Bounded target scan from the container, host-helper LAN enrichment, and a single TCP connection check. |
| `network_http_probe`, `http_headers_audit` | Raw connectivity/timing/body versus authorized security-header assessment. |
| `file_strings`, `binary_analyze` | Whole-file printable strings versus structured binary sections and disassembly. |
| `pcap_analyze`, `suricata_alerts`, `suricata_test_rules` | Traffic views, installed IDS detections, and validation/replay of supplied rules. |
| Trivy, Gitleaks, Semgrep, Syft, YARA, ClamAV | Different findings or artifact inventories; these are not interchangeable scanners. |
| OpenWrt status, Wi-Fi metrics, clients, UCI and ubus | Summary, radio observations, attached clients, configuration and lower-level RPC. |
| Document info, extraction, search | Metadata, broad reading and a targeted excerpt. |
| Image info and metadata | Pixel/format properties versus embedded camera/location tags. |
| Gmail unread count and search | Exact scalar counts versus matching message records. |
| Calendar events and free/busy | Event details versus availability intervals. |
| Drive search, metadata, text and download | Locate an ID, inspect properties, read text or materialize original bytes. |
| Playwright typed actions and generic execution | Small purpose-built schemas remain useful despite generic execution being a superset. |
| Memory read/search/open and create/update/delete | Whole graph, filtering, known IDs and distinct lifecycle operations. |

Owned tools have one concise purpose statement, short operation-specific aliases and schema argument guidance. Namespace descriptions contain service identity only. This keeps stock Pi BM25 from copying unrelated capability keywords into every tool’s search document.
