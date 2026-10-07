# Current owned MCP tool catalog

Generated from shipped tools/list responses.

## system — 56 tools

| Native name | Purpose |
|---|---|
| `mcp__system__pdf_read` | Read PDF text by page with bounded pagination; scanned pages need OCR. Aliases: read PDF pages. |
| `mcp__system__pdf_write` | Create PDF from text or merge, select, reorder and rotate PDF pages. Aliases: write PDF; merge PDF; split PDF. |
| `mcp__system__office_read` | Read Word/OpenDocument text, Excel/Calc cells and formulas, or PowerPoint/Impress slide text. Aliases: read DOC DOCX ODT XLS XLSX ODS PPT PPTX ODP. |
| `mcp__system__office_edit` | Save an edited Office/OpenDocument copy: replace text or update spreadsheet cells and formulas. Aliases: edit Word Excel PowerPoint; edit Writer Calc Impress. |
| `mcp__system__office_export` | Export Office/OpenDocument files to PDF or another format in the same document family. Aliases: Office to PDF; LibreOffice conversion. |
| `mcp__system__local_daily_briefing` | London Ontario daily briefing: current weather, seven-day forecast and CBC London headlines in a Markdown card. Aliases: morning briefing; London local weather news. |
| `mcp__system__docker_list_containers` | List Docker containers with names, state, health, ports and Compose service. Running containers by default. Aliases: docker ps; running containers. |
| `mcp__system__docker_inspect_container` | Inspect one Docker container: configuration, mounts, networks, environment and health. Aliases: container details. |
| `mcp__system__docker_container_logs` | Read recent stdout/stderr logs from a Docker container. Aliases: container startup errors. |
| `mcp__system__docker_container_stats` | Measure one Docker container’s CPU, memory, network and disk I/O. Aliases: container resource usage. |
| `mcp__system__docker_list_images` | List local Docker images, tags, IDs and sizes. Aliases: docker image inventory. |
| `mcp__system__docker_inspect_image` | Inspect a Docker image’s architecture, layers, entrypoint and labels. Aliases: image configuration. |
| `mcp__system__docker_list_networks` | List Docker virtual networks and their drivers. Aliases: container network inventory. |
| `mcp__system__docker_inspect_network` | Inspect one Docker network: IPAM subnets, attached containers and options. Aliases: docker bridge attachments. |
| `mcp__system__docker_list_volumes` | List Docker named volumes and storage drivers. Aliases: persistent container storage. |
| `mcp__system__docker_inspect_volume` | Inspect one Docker volume’s mountpoint, driver and labels. Aliases: volume location. |
| `mcp__system__docker_exec` | Execute a bounded command inside a named Docker container. Requires DOCKER_ALLOW_EXEC=true. Aliases: container command. |
| `mcp__system__docker_container_action` | Start, stop, restart, pause, unpause or kill a Docker container. Requires DOCKER_ALLOW_WRITE=true. Aliases: container lifecycle. |
| `mcp__system__docker_remove_container` | Delete a Docker container, optionally forced. Requires DOCKER_ALLOW_WRITE=true. Aliases: remove stopped container. |
| `mcp__system__docker_remove_image` | Delete a local Docker image by name or ID. Requires DOCKER_ALLOW_WRITE=true. Aliases: remove image tag. |
| `mcp__system__host_snapshot` | Summarize mounted-host health: OS, uptime, CPU load, memory and disk capacity. Aliases: host health overview. |
| `mcp__system__host_cpu_info` | Read mounted-host CPU model, features, load and per-CPU counters. Aliases: processor capabilities. |
| `mcp__system__host_memory_info` | Read mounted-host memory, cache, swap and commit accounting. Aliases: RAM pressure. |
| `mcp__system__host_processes` | List mounted-host processes, sorted by memory, CPU, PID or name. Aliases: process inventory. |
| `mcp__system__host_process_info` | Inspect one mounted-host PID: status, command, threads, limits and file count. Aliases: process details. |
| `mcp__system__host_disk_usage` | Report capacity, used and free space for the mounted host filesystem. Aliases: disk full. |
| `mcp__system__host_read_file` | Read a bounded diagnostic text file under mounted-host /etc, /proc, /sys, /var/log or /run. Aliases: host config file. |
| `mcp__system__network_dns_lookup` | Query one or multiple DNS record types, including PTR and CAA. Returns records grouped by type. Aliases: DNS records; mail policy TXT MX; reverse lookup. |
| `mcp__system__network_ping` | Measure ICMP reachability, loss and latency to a supplied host from the System container. Aliases: ping latency. |
| `mcp__system__network_trace_route` | Trace routed hops to a supplied host from the System container. Aliases: traceroute path. |
| `mcp__system__network_http_probe` | Fetch HTTP status, raw headers, redirects, timing and optional body from a URL using curl. Aliases: HTTP connectivity; response timing. |
| `mcp__system__network_port_check` | Check whether a single TCP port accepts a connection from the System container. Aliases: TCP connection test. |
| `mcp__system__openwrt_targets` | List configured OpenWrt SSH target aliases. Start here when the router target is unknown. Aliases: configured routers; SSH aliases. |
| `mcp__system__openwrt_status` | Read OpenWrt router status: board, uptime, memory, routes and interface state from a known SSH target. Aliases: OpenWrt router health. |
| `mcp__system__openwrt_uci_show` | Read an OpenWrt UCI package or all UCI configuration from a known SSH target. Aliases: router config sections. |
| `mcp__system__openwrt_uci_get` | Read one OpenWrt UCI key from a known SSH target. Aliases: router config value. |
| `mcp__system__openwrt_ubus_call` | Call an OpenWrt ubus object/method on a known SSH target. Aliases: router ubus RPC. |
| `mcp__system__openwrt_logread` | Read recent OpenWrt system log lines from a known SSH target. Aliases: router logs. |
| `mcp__system__openwrt_wifi_status` | Read OpenWrt radio, SSID and associated-station metrics from a known SSH target. Aliases: router radio metrics. |
| `mcp__system__openwrt_clients` | Read DHCP leases, neighbors and associated stations from a known OpenWrt SSH target. Aliases: OpenWrt connected clients. |
| `mcp__system__openwrt_package_query` | List installed or available packages on a known OpenWrt SSH target. Aliases: router opkg packages. |
| `mcp__system__openwrt_service_action` | Control an OpenWrt service on a known SSH target. Requires OPENWRT_ALLOW_WRITE=true. Aliases: restart router service. |
| `mcp__system__openwrt_uci_set` | Set and optionally commit an OpenWrt UCI key on a known SSH target. Requires OPENWRT_ALLOW_WRITE=true. Aliases: change router setting. |
| `mcp__system__image_list` | List workspace images, optionally recursively. Aliases: list image files. |
| `mcp__system__image_info` | Inspect image format, dimensions, color space, alpha and frames. Aliases: pixel geometry. |
| `mcp__system__image_metadata` | Read embedded EXIF, XMP and ICC metadata, camera details and GPS tags. Aliases: photo metadata. |
| `mcp__system__image_resize` | Resize an image or create a proportional thumbnail. Thumbnail mode defaults to shrinking only. Aliases: image thumbnail; scale image. |
| `mcp__system__image_crop` | Crop a rectangular region from a workspace image and write a new image. Aliases: extract image region. |
| `mcp__system__image_convert` | Encode a workspace image in another format with optional quality control. Aliases: image format conversion. |
| `mcp__system__image_compare` | Compare two images using RMSE and optionally write a difference image. Aliases: pixel difference. |
| `mcp__system__document_list` | List workspace documents, optionally including subdirectories. Aliases: find document files. |
| `mcp__system__document_info` | Inspect document format, file size and PDF metadata/page count. Aliases: document properties. |
| `mcp__system__document_extract_text` | Extract readable text from a workspace document for reading or summarization. Aliases: read PDF DOCX text. |
| `mcp__system__document_search_text` | Search document text for a phrase or regex and return matching context. Aliases: search inside document. |
| `mcp__system__document_convert` | Convert a document with Pandoc and write the requested output format. Aliases: document format conversion. |
| `mcp__system__document_render_pdf_page` | Render one PDF page to a PNG image at a chosen resolution. Aliases: PDF page preview. |

## security — 63 tools

| Native name | Purpose |
|---|---|
| `mcp__security__status` | Check installed executables, host-helper availability, Firecrawl configuration and background-job capacity. Aliases: backend availability. |
| `mcp__security__firecrawl_scrape` | Fetch one web page as clean Markdown through the configured Firecrawl backend; credentials stay server-side. Aliases: website readable content. |
| `mcp__security__firecrawl_map` | Enumerate website URLs through the configured Firecrawl backend. Aliases: website URL inventory. |
| `mcp__security__subdomain_enum` | Find subdomains in public sources with passive Subfinder OSINT. Aliases: passive subdomains. |
| `mcp__security__exploit_search` | Search the local Exploit-DB catalogue by CVE or service version; returns references only. Aliases: Searchsploit lookup. |
| `mcp__security__exploit_source` | Read an Exploit-DB source excerpt by EDB ID for analysis. Aliases: review exploit code. |
| `mcp__security__sqlmap` | Run bounded SQL-injection detection or explicitly requested database-name enumeration on an authorized URL. Aliases: sqlmap injection test. |
| `mcp__security__metasploit_info` | Inspect a Metasploit module’s help and options. Aliases: msfconsole module details. |
| `mcp__security__metasploit_run` | Check or run a Metasploit module on one authorized target. Returns a background job ID for job_status. Aliases: Metasploit module execution. |
| `mcp__security__listener_start` | Start a bounded Netcat or Socat callback listener on a published container port. Returns a background job ID. Aliases: TCP callback listener. |
| `mcp__security__job_status` | Read a background job’s status and output page; continue using next_offset. Aliases: poll job output. |
| `mcp__security__job_send` | Send text to an existing interactive listener job. Aliases: write listener input. |
| `mcp__security__job_stop` | Stop a background job and its child processes. Aliases: cancel running job. |
| `mcp__security__jq` | Filter a workspace JSON or JSONL file with a bounded jq expression. Aliases: JSON query. |
| `mcp__security__pcap_analyze` | Analyze a saved PCAP with Tshark: protocol hierarchy, endpoint conversations or selected packet fields. Aliases: analyze PCAP; top talkers; packet field extraction. |
| `mcp__security__suricata_test_rules` | Validate Suricata rules and optionally replay only those rules against a saved PCAP with hit statistics. Aliases: IDS rule testing. |
| `mcp__security__osquery` | Run a read-only SQL query through osqueryi inside the Security container. Aliases: container osquery SQL. |
| `mcp__security__binary_analyze` | Inspect binary metadata, imports, exports, section strings, functions or disassembly using sandboxed Radare2. Aliases: binary structure analysis. |
| `mcp__security__mdns_discover` | Probe mDNS/DNS-SD services on a specified target, or multicast within the Security-container namespace. Aliases: Zeroconf service TXT. |
| `mcp__security__upnp_discover` | Probe a target for UPnP/SSDP device metadata, or multicast within the Security-container namespace. Aliases: UPnP product description. |
| `mcp__security__dhcp_discover` | Read DHCP options using target DHCPINFORM, or broadcast within the Security-container namespace. Aliases: DHCP server options. |
| `mcp__security__dhcp6_discover` | Read DHCPv6 advertisements by multicast within the Security-container namespace. Aliases: DHCPv6 options. |
| `mcp__security__dns_audit` | Audit an authorized DNS server’s recursion, DNSSEC, NSID and optional AXFR zone-transfer behavior. Aliases: DNS server posture. |
| `mcp__security__snmp_discover` | Read SNMP system identification from an authorized target using bounded probes. Aliases: SNMP system metadata. |
| `mcp__security__snmp_interfaces` | Read interface addresses and link metadata exposed by an authorized SNMP target. Aliases: SNMP interface table. |
| `mcp__security__smb_audit` | Audit SMB dialects, signing and anonymous server metadata on an authorized target. Aliases: SMB signing posture. |
| `mcp__security__smb_shares` | Enumerate SMB shares and anonymous-access metadata on an authorized target. Aliases: SMB share permissions. |
| `mcp__security__ntp_discover` | Read NTP time, stratum, reference ID and implementation details from an authorized target. Aliases: NTP server information. |
| `mcp__security__ldap_discover` | Read LDAP RootDSE capabilities, naming contexts and authentication mechanisms from an authorized target. Aliases: directory server RootDSE. |
| `mcp__security__protocol_observe` | Passively observe LLDP, CDP or LLMNR/NBNS packets on a Security-container interface. Requires packet-capture permission. Aliases: passive protocol advertisements. |
| `mcp__security__wsd_discover` | Probe WS-Discovery endpoints on a specified target, or multicast within the Security-container namespace. Aliases: WSD printer endpoints. |
| `mcp__security__arp_discover` | Probe authorized IPv4 targets using ARP within the Security-container broadcast domain. Aliases: ARP neighbor sweep. |
| `mcp__security__ndp_discover` | Read the IPv6 neighbor cache of the Security-container namespace. Aliases: NDP cached neighbors. |
| `mcp__security__observe_broadcast_multicast` | Passively capture host ARP broadcasts and mDNS, LLMNR, SSDP multicast. Separates packet sources from address/name/service claims; sends no probes. Requires host capture permission; visibility does not prove failed isolation. Aliases: broadcast multicast leakage; passive ARP hostname services. |
| `mcp__security__probe_gateway_proxy_arp` | Bounded host ARP sweep on a connected IPv4 prefix; compares replies with gateway MAC to identify Proxy ARP candidates. Gateway replies do not confirm peer liveness. Aliases: gateway proxy ARP; shared ARP responder MAC. |
| `mcp__security__probe_gateway_hairpin` | Compare direct and gateway-addressed Ethernet ICMP probes to explicit same-subnet peers, with TTL=1 forwarding control. Reports possible hairpin routing; controlled peers and policy evidence are needed to confirm isolation bypass. Aliases: gateway hairpin routing; client isolation path comparison. |
| `mcp__security__observe_dns_cache` | Observe explicit names at an authorized LAN DNS server using nonrecursive queries. Returns validated responses, TTLs and timings; optional supplied TTL baseline. Cache data cannot identify a requesting client or confirm device presence. Aliases: DNS cache snooping; nonrecursive cache evidence. |
| `mcp__security__discover_mdns_subnets` | Discover advertised host addresses and candidate subnet ranges through host mDNS/DNS-SD. Returns compact report rows, saves full raw audit evidence separately, distinguishes local prefixes, routing coverage and heuristic grouping, and treats outside-subnet advertisements as possible reflection rather than proof. Does not scan candidates. Aliases: mDNS subnet discovery; subnet ranges from advertised addresses; mDNS reflector evidence. |
| `mcp__security__get_host_interface_info` | Start local network reconnaissance here: inspect the laptop’s physical Ethernet/Wi-Fi interfaces, addresses, gateway, DNS and link speed through the required host helper. Aliases: host network state; active laptop interfaces; network reconnaissance and mapping workflow. |
| `mcp__security__perform_network_discovery` | Discover and enumerate hosts on authorized local subnets through the required host helper. Full mode adds names, MAC/vendor, OS evidence, ports/services, shares and media devices. Aliases: LAN reconnaissance; comprehensive network discovery; reachable host inventory. |
| `mcp__security__analyze_network_topology` | Analyze physical network topology through the required host helper: subnets, routes, gateways, mDNS visibility and optional LLDP/CDP or peer-isolation evidence. Virtual interfaces and VLANs are excluded. Aliases: routing relationships; network segmentation. |
| `mcp__security__analyze_wireless_environment` | Assess laptop Wi-Fi through the required host helper: SSID/BSSID, signal, link rate, channel width, nearby access points and channel overlap. Passive cached observations by default. Aliases: passive wireless assessment; wifi survey; wireless network assessment. |
| `mcp__security__generate_graphical_network_map` | Render collected network reconnaissance data into Graphviz SVG and HTML topology maps. Pass returned observation_path values as input_paths; no JSON copying needed. Aliases: graphical network map; network mapping; topology diagram. |
| `mcp__security__port_scan` | Scan authorized TCP targets from the Security container. Enable service_detection for product/version fingerprints. Aliases: TCP open ports; service version detection. |
| `mcp__security__tls_audit` | Audit TLS protocol support, certificates and cipher suites on an authorized service. Aliases: SSL configuration. |
| `mcp__security__http_headers_audit` | Audit CSP, HSTS, frame protection and other HTTP response headers on an authorized URL. Aliases: web security headers. |
| `mcp__security__web_server_audit` | Check an authorized web server for exposed files and risky defaults using bounded Nikto probes. Aliases: Nikto misconfiguration. |
| `mcp__security__vulnerability_scan` | Scan an authorized URL with bounded Nuclei CVE and misconfiguration templates. Aliases: known vulnerability detection. |
| `mcp__security__web_content_discover` | Probe paths on an authorized website using bounded ffuf requests and an explicit status-code filter. Aliases: web directory fuzzing. |
| `mcp__security__workspace_vuln_scan` | Scan workspace dependencies, IaC and secrets using Trivy; choose scanners to control coverage. Aliases: dependency vulnerabilities; configuration audit. |
| `mcp__security__secret_scan` | Scan current workspace files with Gitleaks for exposed credentials. Returns redacted findings; excludes Git history. Aliases: credential leak detection. |
| `mcp__security__code_scan` | Analyze workspace source for insecure coding patterns using Semgrep. Aliases: static application analysis. |
| `mcp__security__generate_sbom` | Inventory workspace software packages with Syft and optionally save a CycloneDX SBOM. Aliases: software bill of materials. |
| `mcp__security__yara_scan` | Match YARA rules against workspace files using bundled or supplied rules. Aliases: artifact pattern signatures. |
| `mcp__security__malware_scan` | Scan workspace files with ClamAV and report detected signatures. Aliases: antivirus file scan. |
| `mcp__security__file_hash` | Compute a workspace file’s SHA-256, SHA-512 or MD5 digest. Aliases: file integrity checksum. |
| `mcp__security__file_strings` | Extract printable strings from the entire raw file, including data outside recognized binary sections. Aliases: raw artifact strings. |
| `mcp__security__packet_capture` | Record bounded traffic on a Security-container interface into a workspace PCAP. Requires SECURITY_ALLOW_PACKET_CAPTURE=true. Aliases: tcpdump capture. |
| `mcp__security__network_interfaces` | Inspect Security-container interfaces and routes for container diagnostics or choosing a packet-capture interface. Aliases: container interface list. |
| `mcp__security__suricata_alerts` | Run Suricata IDS on a saved capture using the installed ruleset; return alert and event counts. Aliases: offline IDS alerts. |
| `mcp__security__host_log_search` | Find text or regex matches in an allowlisted mounted-host /var/log file. Aliases: authentication log evidence. |
| `mcp__security__workspace_ioc_search` | Search workspace text files recursively for one literal indicator. Aliases: IOC scoping. |
| `mcp__security__host_audit` | Audit mounted-host filesystem hardening with Lynis and summarize warnings and suggestions. Aliases: host hardening review. |

## google — 23 tools

| Native name | Purpose |
|---|---|
| `mcp__google__auth_status` | Check Google OAuth configuration and granted scopes; credentials remain server-side. Aliases: Google account authentication. |
| `mcp__google__gmail_get_unread_count` | Return exact unread Gmail message and thread counts. Aliases: how many unread emails. |
| `mcp__google__gmail_search_messages` | Find Gmail messages with a query; return matching records, metadata and snippets. Aliases: find email. |
| `mcp__google__gmail_get_message` | Read one Gmail message by ID, including headers and optional decoded body. Aliases: email content. |
| `mcp__google__gmail_get_thread` | Read all messages in a Gmail conversation thread. Aliases: email conversation. |
| `mcp__google__gmail_list_labels` | List Gmail system and user labels with their IDs. Aliases: mailbox labels. |
| `mcp__google__gmail_create_draft` | Create an unsent Gmail draft. Requires Gmail writes and a matching OAuth scope. Aliases: draft email. |
| `mcp__google__gmail_send_draft` | Send an existing Gmail draft by ID. Requires Gmail writes and a send scope. Aliases: send prepared email. |
| `mcp__google__gmail_modify_labels` | Add or remove labels on a Gmail message. Requires Gmail writes. Aliases: archive mark read star. |
| `mcp__google__calendar_list_calendars` | List accessible Google calendars and their IDs. Aliases: available calendars. |
| `mcp__google__calendar_list_events` | List Google Calendar events in a time range; omitted lower bound starts at the current time for upcoming events. Aliases: upcoming meetings; calendar agenda; next calendar events. |
| `mcp__google__calendar_get_event` | Read one Google Calendar event’s complete details. Aliases: meeting details. |
| `mcp__google__calendar_freebusy` | Read busy intervals for one or more calendars over a requested period. Aliases: calendar availability; meeting conflicts. |
| `mcp__google__calendar_create_event` | Create a Google Calendar event. Requires Calendar writes and a matching OAuth scope. Aliases: schedule meeting. |
| `mcp__google__calendar_update_event` | Update selected fields of an existing Google Calendar event. Requires Calendar writes. Aliases: reschedule event. |
| `mcp__google__calendar_delete_event` | Delete a Google Calendar event. Requires Calendar writes. Aliases: cancel calendar event. |
| `mcp__google__drive_search_files` | Find Google Drive files or folders and return IDs and metadata. Aliases: find Drive document. |
| `mcp__google__drive_get_file_metadata` | Read metadata for a known Google Drive file ID. Aliases: Drive file properties. |
| `mcp__google__drive_read_text` | Read text from a known Drive file or exportable Google document. Aliases: Google Docs content. |
| `mcp__google__drive_download_file` | Save a Drive file’s original bytes or export a Google document to the workspace. Aliases: download PDF image attachment. |
| `mcp__google__drive_create_folder` | Create a folder in Google Drive. Requires Drive writes. Aliases: new Drive folder. |
| `mcp__google__drive_upload_file` | Upload a workspace file to Google Drive. Requires Drive writes. Aliases: save file to Drive. |
| `mcp__google__drive_delete_file` | Delete a Google Drive file by ID. Requires Drive writes. Aliases: remove Drive file. |
