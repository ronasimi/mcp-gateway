#!/usr/bin/env node
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const WORKSPACE = path.resolve(process.env.MCP_WORKSPACE || '/workspace');
const HOST_ROOT = path.resolve(process.env.MCP_HOST_ROOT || '/host');
const SSH_CONFIG = process.env.OPENWRT_SSH_CONFIG || '/data/ssh/config';
const DOCKER_SOCKET = process.env.DOCKER_SOCKET || '/var/run/docker.sock';
const MAX_OUTPUT = Number(process.env.SYSTEM_TOOLS_MAX_OUTPUT || 65536);
const DEFAULT_TIMEOUT = Number(process.env.SYSTEM_TOOLS_TIMEOUT_MS || 30000);
const DOCKER_ALLOW_WRITE = /^(1|true|yes)$/i.test(process.env.DOCKER_ALLOW_WRITE || 'false');
const DOCKER_ALLOW_EXEC = /^(1|true|yes)$/i.test(process.env.DOCKER_ALLOW_EXEC || 'false');
const OPENWRT_ALLOW_WRITE = /^(1|true|yes)$/i.test(process.env.OPENWRT_ALLOW_WRITE || 'false');

const s = (description, properties = {}, required = []) => ({ type: 'object', description, properties, required, additionalProperties: false });
const str = (description, extra={}) => ({ type: 'string', description, ...extra });
const num = (description, extra={}) => ({ type: 'number', description, ...extra });
const bool = (description) => ({ type: 'boolean', description });
const arr = (description, items) => ({ type: 'array', description, items });

const TOOLS = [
  // Docker
  { name:'docker_list_containers', description:'Docker container summary: list running containers by default with compact names, image, state, status, health, ports, networks, and Compose project/service. Use for docker ps, what containers are running, container inventory, or finding a container before logs/inspect. Set all=true only when stopped containers are also requested.', inputSchema:s('List Docker containers in a compact normalized form.', {all:bool('Include stopped containers too; default false.')}) },
  { name:'docker_inspect_container', description:'Docker container inspect: return detailed configuration, mounts, networks, health, state, environment, labels, and runtime metadata for one container by name or ID.', inputSchema:s('Inspect one Docker container.', {container:str('Container name or ID.')}, ['container']) },
  { name:'docker_container_logs', description:'Docker logs: read recent stdout/stderr logs from a container. Use for service failures, stack traces, startup errors, health checks, and application diagnostics.', inputSchema:s('Read Docker container logs.', {container:str('Container name or ID.'), tail:num('Number of log lines; default 200.',{minimum:1,maximum:5000}), since:str('Docker-compatible time or duration, e.g. 10m, 2h, 2026-09-30T12:00:00Z.')}, ['container']) },
  { name:'docker_container_stats', description:'Docker stats: get one-shot CPU, memory, network I/O, block I/O, PID, and memory-limit metrics for a container.', inputSchema:s('Get container resource usage.', {container:str('Container name or ID.')}, ['container']) },
  { name:'docker_list_images', description:'Docker images: list local images with repository tags, IDs, creation time, and sizes. Use for image inventory, tag lookup, disk usage, or model/service deployment checks.', inputSchema:s('List Docker images.', {}) },
  { name:'docker_inspect_image', description:'Docker image inspect: return architecture, OS, layers, config, labels, entrypoint, command, size, and repo tags for an image name, tag, or ID.', inputSchema:s('Inspect one Docker image.', {image:str('Image name, tag, digest, or ID.')}, ['image']) },
  { name:'docker_list_networks', description:'Docker networks: list bridge/overlay/macvlan networks, drivers, scopes, IDs, and names. Use for container DNS/connectivity and network attachment troubleshooting.', inputSchema:s('List Docker networks.', {}) },
  { name:'docker_inspect_network', description:'Docker network inspect: show subnet/IPAM, connected containers, aliases, options, and driver configuration for one Docker network.', inputSchema:s('Inspect one Docker network.', {network:str('Docker network name or ID.')}, ['network']) },
  { name:'docker_list_volumes', description:'Docker volumes: list named volumes and drivers. Use for persistent-data discovery, storage troubleshooting, and locating service state.', inputSchema:s('List Docker volumes.', {}) },
  { name:'docker_inspect_volume', description:'Docker volume inspect: show mountpoint, driver, labels, options, and scope for one Docker named volume.', inputSchema:s('Inspect one Docker volume.', {volume:str('Docker volume name.')}, ['volume']) },
  { name:'docker_exec', description:'Docker exec: run a bounded command inside an existing container and return its output. Use for in-container diagnostics such as checking files, processes, versions, or health commands. Disabled unless DOCKER_ALLOW_EXEC=true.', inputSchema:s('Execute a command inside a Docker container.', {container:str('Container name or ID.'), command:str('Command string executed with /bin/sh -lc.'), timeout:num('Timeout seconds; default 30.',{minimum:1,maximum:300})}, ['container','command']) },
  { name:'docker_container_action', description:'Docker container lifecycle: start, stop, restart, pause, unpause, or kill a container. Mutating actions are disabled unless DOCKER_ALLOW_WRITE=true.', inputSchema:s('Perform a Docker lifecycle action.', {container:str('Container name or ID.'), action:str('Lifecycle action.',{enum:['start','stop','restart','pause','unpause','kill']}), timeout:num('Stop/restart timeout seconds.',{minimum:0,maximum:300})}, ['container','action']) },
  { name:'docker_remove_container', description:'Docker container remove: delete a stopped container, optionally force. Disabled unless DOCKER_ALLOW_WRITE=true. Use only when removal is explicitly required.', inputSchema:s('Remove a Docker container.', {container:str('Container name or ID.'), force:bool('Force removal of a running container.')}, ['container']) },
  { name:'docker_remove_image', description:'Docker image remove: delete a local image by name/tag/ID, optionally force. Disabled unless DOCKER_ALLOW_WRITE=true.', inputSchema:s('Remove a Docker image.', {image:str('Image name, tag, digest, or ID.'), force:bool('Force removal.')}, ['image']) },


  // Host
  { name:'host_snapshot', description:'Host system snapshot: summarize hostname, kernel, uptime, load average, CPU count, memory/swap, filesystem usage, and basic OS identity from the mounted host. Use first for general host health or performance triage.', inputSchema:s('Get a concise host health snapshot.', {}) },
  { name:'host_cpu_info', description:'Host CPU details: model, logical processors, flags/features, current load, and per-CPU times from /proc. Use for CPU capability, saturation, virtualization, and architecture checks.', inputSchema:s('Read host CPU information.', {}) },
  { name:'host_memory_info', description:'Host memory: parse /proc/meminfo for total, available, cached, buffers, swap, dirty, committed, and huge-page values. Use for memory pressure and capacity diagnosis.', inputSchema:s('Read host memory information.', {}) },
  { name:'host_processes', description:'Host processes: list processes from host /proc with PID, command, state, RSS, CPU time, and executable/cmdline where readable. Use for process discovery, CPU/RAM troubleshooting, or checking whether a service is running.', inputSchema:s('List host processes.', {limit:num('Maximum processes returned; default 80.',{minimum:1,maximum:500}), sort_by:str('Sort key.',{enum:['rss','cpu','pid','name']})}) },
  { name:'host_process_info', description:'Host process inspect: return status, cmdline, executable, environment subset, open-file count, threads, memory, and CPU accounting for one host PID.', inputSchema:s('Inspect one host process.', {pid:num('Host PID.',{minimum:1})}, ['pid']) },
  { name:'host_network_info', description:'Host network snapshot: read host kernel interface counters, IPv4 routes, ARP/neighbor cache, and resolver configuration from mounted /proc and /etc. Use when container-side network_interfaces is not representative of the host.', inputSchema:s('Read host network state.', {}) },
  { name:'host_disk_usage', description:'Host filesystem usage: report mounted filesystems and disk capacity/free/used percentages from the host root mount. Use for low-disk-space and mount troubleshooting.', inputSchema:s('Read host filesystem usage.', {}) },
  { name:'host_read_file', description:'Host diagnostic file read: read a bounded text file under host /etc, /proc, /sys, /var/log, or /run. Use for configs and diagnostics when a dedicated host tool is not enough; binary files are rejected.', inputSchema:s('Read an allowlisted host text file.', {path:str('Absolute host path such as /etc/os-release or /proc/loadavg.'), max_bytes:num('Maximum bytes to read; default 32768.',{minimum:1,maximum:131072})}, ['path']) },

  // Network
  { name:'network_dns_lookup', description:'DNS lookup: resolve A/AAAA/CNAME/MX/TXT/NS records for a hostname or domain. Use for DNS failures, name resolution, mail records, aliases, or verifying local DNS.', inputSchema:s('Resolve DNS records.', {name:str('Hostname or domain.'), type:str('DNS record type.',{enum:['A','AAAA','CNAME','MX','TXT','NS','SOA','PTR']})}, ['name']) },
  { name:'network_ping', description:'Network ping: test ICMP reachability and latency to a host/IP with packet loss and round-trip timing. Use for LAN/Internet connectivity diagnosis.', inputSchema:s('Ping a host.', {host:str('Hostname or IP address.'), count:num('Packets; default 4.',{minimum:1,maximum:20}), timeout:num('Per-packet timeout seconds; default 2.',{minimum:1,maximum:10})}, ['host']) },
  { name:'network_trace_route', description:'Traceroute: show network path and hop latency to a host/IP. Use for routing, latency, ISP path, or unreachable-network diagnosis.', inputSchema:s('Trace route to a host.', {host:str('Hostname or IP address.'), max_hops:num('Maximum hops; default 20.',{minimum:1,maximum:64})}, ['host']) },
  { name:'network_http_probe', description:'HTTP/HTTPS probe: fetch headers/status/timing and optionally a bounded response body from a URL. Use for endpoint health, redirects, TLS reachability, APIs, and local web services.', inputSchema:s('Probe an HTTP endpoint.', {url:str('http:// or https:// URL.'), method:str('HTTP method.',{enum:['GET','HEAD']}), body:bool('Include a bounded response body for GET.')}, ['url']) },
  { name:'network_port_check', description:'TCP port check: test whether a host:port accepts a TCP connection and report connection latency. Use for SSH, web, database, router, and service reachability.', inputSchema:s('Check one TCP port.', {host:str('Hostname or IP.'), port:num('TCP port.',{minimum:1,maximum:65535}), timeout:num('Timeout seconds; default 3.',{minimum:1,maximum:30})}, ['host','port']) },
  { name:'network_scan_ports', description:'Nmap port scan: scan a host or CIDR for open TCP ports with bounded timing. Use for LAN service discovery, exposed-port inventory, and troubleshooting. Targets are user-supplied; no Internet-wide scanning.', inputSchema:s('Run a bounded nmap TCP scan.', {target:str('Host, IP, or CIDR.'), ports:str('Port expression, e.g. 22,80,443 or 1-1024; default top ports.'), service_detection:bool('Enable -sV service/version detection.')}, ['target']) },
  { name:'network_interfaces', description:'Network interfaces: show container-side interface addresses, routes, links, and neighbor table. Use to understand the MCP gateway network namespace and ai-local connectivity.', inputSchema:s('Show network interfaces and routes.', {}) },

  // OpenWrt
  { name:'openwrt_status', description:'OpenWrt router status: via SSH, return uptime, release/version, board info, load, memory, mounts, interfaces, routes, and key ubus system/network status. Use first for router health checks.', inputSchema:s('Get OpenWrt system status.', {target:str('SSH host alias from the mounted OpenWrt SSH config, e.g. anansi or arachne.')}, ['target']) },
  { name:'openwrt_uci_show', description:'OpenWrt UCI configuration: show all config or one package such as network, wireless, firewall, dhcp, system, minidlna. Use for router configuration inspection and troubleshooting.', inputSchema:s('Show OpenWrt UCI config.', {target:str('SSH host alias.'), package:str('Optional UCI package name such as network, wireless, firewall, dhcp, system.')}, ['target']) },
  { name:'openwrt_uci_get', description:'OpenWrt UCI value: read one exact option, e.g. network.lan.ipaddr or wireless.@wifi-iface[0].ssid. Use when a precise router setting is needed.', inputSchema:s('Read one UCI setting.', {target:str('SSH host alias.'), key:str('UCI key.')}, ['target','key']) },
  { name:'openwrt_ubus_call', description:'OpenWrt ubus RPC: call an ubus object/method with JSON arguments, e.g. system board, network.interface dump, network.wireless status. Useful for structured live router state.', inputSchema:s('Call OpenWrt ubus.', {target:str('SSH host alias.'), object:str('ubus object.'), method:str('ubus method.'), args:str('JSON object string; default {}.')}, ['target','object','method']) },
  { name:'openwrt_logread', description:'OpenWrt logs: read recent system log lines via logread, optionally filter by a case-insensitive text pattern. Use for Wi-Fi, DHCP, firewall, kernel, service, or boot troubleshooting.', inputSchema:s('Read OpenWrt logs.', {target:str('SSH host alias.'), lines:num('Recent lines; default 200.',{minimum:1,maximum:3000}), filter:str('Optional grep text.')}, ['target']) },
  { name:'openwrt_wifi_status', description:'OpenWrt Wi-Fi status: return ubus wireless state plus iwinfo summaries when available. Use for radios, SSIDs, channels, clients, signal, association, and wireless troubleshooting.', inputSchema:s('Read OpenWrt wireless status.', {target:str('SSH host alias.')}, ['target']) },
  { name:'openwrt_clients', description:'OpenWrt connected clients: collect DHCP leases, IP neighbor/ARP entries, and Wi-Fi association lists when available. Use to find LAN devices, client IP/MAC mappings, and wireless stations.', inputSchema:s('List OpenWrt LAN/Wi-Fi clients.', {target:str('SSH host alias.')}, ['target']) },
  { name:'openwrt_package_query', description:'OpenWrt package query: list installed opkg packages or search package names/descriptions without changing the router. Use for checking whether a package such as minidlna, luci, kmod, or a utility is installed.', inputSchema:s('Query OpenWrt opkg packages.', {target:str('SSH host alias.'), mode:str('Query mode.',{enum:['installed','search']}), query:str('Optional case-insensitive package filter.')}, ['target','mode']) },
  { name:'openwrt_service_action', description:'OpenWrt service control: start, stop, restart, reload, enable, or disable an /etc/init.d service. Disabled unless OPENWRT_ALLOW_WRITE=true.', inputSchema:s('Control one OpenWrt init service.', {target:str('SSH host alias.'), service:str('Init script/service name.'), action:str('Service action.',{enum:['start','stop','restart','reload','enable','disable']})}, ['target','service','action']) },
  { name:'openwrt_uci_set', description:'OpenWrt UCI write: set one UCI key=value and optionally commit its package. Disabled unless OPENWRT_ALLOW_WRITE=true. Use for explicit router configuration changes.', inputSchema:s('Set one OpenWrt UCI value.', {target:str('SSH host alias.'), key:str('UCI key.'), value:str('New value.'), commit:bool('Commit the containing UCI package after setting.')}, ['target','key','value']) },

  // Images
  { name:'image_list', description:'Image files: list PNG/JPEG/WebP/GIF/TIFF/BMP/SVG files in the MCP workspace, optionally under a subdirectory. Use to discover available images before inspecting or editing.', inputSchema:s('List workspace image files.', {directory:str('Workspace-relative directory; default .'), recursive:bool('Recurse into subdirectories.')}) },
  { name:'image_info', description:'Image inspect: report format, width, height, color space, alpha, bit depth, file size, and frame/page count for a workspace image. Use before resize/crop/convert.', inputSchema:s('Inspect an image.', {path:str('Workspace-relative image path.')}, ['path']) },
  { name:'image_metadata', description:'Image metadata/EXIF: extract camera, timestamp, orientation, GPS, dimensions, ICC, and other available metadata from a workspace image using exiftool.', inputSchema:s('Read image metadata.', {path:str('Workspace-relative image path.')}, ['path']) },
  { name:'image_resize', description:'Image resize: create a resized copy of a workspace image using ImageMagick. Supports exact WxH or bounded geometry such as 1920x1080>. Output remains inside the workspace.', inputSchema:s('Resize an image.', {input:str('Workspace-relative input image.'), output:str('Workspace-relative output image.'), geometry:str('ImageMagick geometry, e.g. 1024x1024, 1920x1080>, 50%.')}, ['input','output','geometry']) },
  { name:'image_crop', description:'Image crop: create a cropped copy using width, height, x, and y coordinates. Use for extracting a region or trimming an image. Output remains inside the workspace.', inputSchema:s('Crop an image.', {input:str('Workspace-relative input image.'), output:str('Workspace-relative output image.'), width:num('Crop width pixels.',{minimum:1}), height:num('Crop height pixels.',{minimum:1}), x:num('Left offset pixels.',{minimum:0}), y:num('Top offset pixels.',{minimum:0})}, ['input','output','width','height','x','y']) },
  { name:'image_convert', description:'Image format convert: convert a workspace image between PNG, JPEG, WebP, GIF, TIFF, BMP, or PDF-compatible raster output. Output format is inferred from extension.', inputSchema:s('Convert an image file.', {input:str('Workspace-relative input image.'), output:str('Workspace-relative output image.'), quality:num('Optional quality 1-100 for lossy formats.',{minimum:1,maximum:100})}, ['input','output']) },
  { name:'image_compare', description:'Image compare: calculate ImageMagick RMSE difference between two workspace images and optionally write a visual diff image. Use to verify edits, compare renders, or detect image changes.', inputSchema:s('Compare two images.', {left:str('First workspace-relative image.'), right:str('Second workspace-relative image.'), diff_output:str('Optional workspace-relative diff image path.')}, ['left','right']) },
  { name:'image_thumbnail', description:'Image thumbnail: create a proportional thumbnail constrained to max width/height, preserving aspect ratio and avoiding enlargement unless requested.', inputSchema:s('Create an image thumbnail.', {input:str('Workspace-relative input image.'), output:str('Workspace-relative output image.'), width:num('Maximum width.',{minimum:1}), height:num('Maximum height.',{minimum:1}), enlarge:bool('Allow enlarging smaller images; default false.')}, ['input','output','width','height']) },

  // Documents
  { name:'document_list', description:'Documents: list PDF, DOCX, ODT, RTF, HTML, Markdown, text, CSV, XLSX, PPTX, EPUB and related files in the MCP workspace. Use to discover files before extraction or conversion.', inputSchema:s('List workspace document files.', {directory:str('Workspace-relative directory; default .'), recursive:bool('Recurse into subdirectories.')}) },
  { name:'document_info', description:'Document inspect: identify MIME/type, size, modification time, and format-specific metadata such as PDF pages/title/author. Use before text extraction or rendering.', inputSchema:s('Inspect a document.', {path:str('Workspace-relative document path.')}, ['path']) },
  { name:'document_extract_text', description:'Document text extraction: extract readable text from PDF, DOCX, ODT, RTF, HTML, EPUB, Markdown, plain text, CSV, PPTX, or XLSX using pdftotext/pandoc/unzip fallbacks. Output is bounded.', inputSchema:s('Extract document text.', {path:str('Workspace-relative document path.'), max_chars:num('Maximum characters returned; default 60000.',{minimum:100,maximum:200000})}, ['path']) },
  { name:'document_search_text', description:'Document search: extract text then return matching lines with context for a literal or regular-expression query. Use for finding facts, headings, names, errors, or clauses inside a document.', inputSchema:s('Search within a document.', {path:str('Workspace-relative document path.'), query:str('Search text or regular expression.'), regex:bool('Treat query as a regular expression.'), context:num('Context lines around each match; default 2.',{minimum:0,maximum:10}), max_matches:num('Maximum matches; default 50.',{minimum:1,maximum:200})}, ['path','query']) },
  { name:'document_convert', description:'Document convert: use pandoc to convert a workspace document to Markdown, plain text, HTML, DOCX, EPUB, or other supported pandoc output format. Output stays inside the workspace.', inputSchema:s('Convert a document with pandoc.', {input:str('Workspace-relative input file.'), output:str('Workspace-relative output file.'), to:str('Optional pandoc output format override, e.g. markdown, plain, html, docx, epub.')}, ['input','output']) },
  { name:'document_render_pdf_page', description:'PDF page render: render one PDF page to PNG at a chosen DPI using pdftoppm. Use when page layout, figures, scans, or visual inspection matters. Output stays inside the workspace.', inputSchema:s('Render one PDF page to PNG.', {input:str('Workspace-relative PDF path.'), page:num('1-based page number.',{minimum:1}), output:str('Workspace-relative PNG output path.'), dpi:num('Render DPI; default 144.',{minimum:36,maximum:600})}, ['input','page','output']) },
];


const SYSTEM_MUTATING = new Set([
  'docker_exec','docker_container_action','docker_remove_container','docker_remove_image',
  'openwrt_service_action','openwrt_uci_set',
  'image_resize','image_crop','image_convert','image_thumbnail',
  'document_convert','document_render_pdf_page',
]);
const SYSTEM_DESTRUCTIVE = new Set(['docker_remove_container','docker_remove_image']);
const SYSTEM_OPEN_WORLD = new Set([
  'network_dns_lookup','network_ping','network_trace_route','network_http_probe','network_port_check','network_scan_ports',
  'openwrt_status','openwrt_uci_show','openwrt_uci_get','openwrt_ubus_call','openwrt_logread','openwrt_wifi_status','openwrt_clients','openwrt_package_query','openwrt_service_action','openwrt_uci_set',
]);
for (const tool of TOOLS) {
  const mutating = SYSTEM_MUTATING.has(tool.name);
  tool.annotations = {
    readOnlyHint: !mutating,
    destructiveHint: SYSTEM_DESTRUCTIVE.has(tool.name),
    idempotentHint: !mutating || ['image_resize','image_crop','image_convert','image_thumbnail','document_convert','document_render_pdf_page'].includes(tool.name),
    openWorldHint: SYSTEM_OPEN_WORLD.has(tool.name),
  };
}

const toolMap = new Map(TOOLS.map(t => [t.name,t]));

function clip(value, max=MAX_OUTPUT) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  if (Buffer.byteLength(text) <= max) return text;
  return text.slice(0, max) + `\n...[truncated at ${max} bytes]`;
}

async function run(cmd, args=[], opts={}) {
  const { stdout='', stderr='' } = await execFileAsync(cmd, args.map(String), {
    timeout: opts.timeout ?? DEFAULT_TIMEOUT,
    maxBuffer: opts.maxBuffer ?? 4*1024*1024,
    env: { ...process.env, ...(opts.env||{}) },
  });
  return clip([stdout.trim(), stderr.trim()].filter(Boolean).join('\n'));
}

function safeWorkspace(rel, {mustExist=false}={}) {
  if (typeof rel !== 'string' || rel.includes('\0')) throw new Error('path must be a string without NUL bytes');
  const resolved = path.resolve(WORKSPACE, rel);
  if (!(resolved === WORKSPACE || resolved.startsWith(WORKSPACE + path.sep))) throw new Error('path escapes MCP workspace');
  if (mustExist && !fs.existsSync(resolved)) throw new Error(`workspace path not found: ${rel}`);
  return resolved;
}

function hostPath(p) {
  if (typeof p !== 'string' || !p.startsWith('/') || p.includes('\0')) throw new Error('host path must be absolute');
  const allowed = ['/etc','/proc','/sys','/var/log','/run'];
  if (!allowed.some(prefix => p === prefix || p.startsWith(prefix + '/'))) throw new Error(`host path not allowlisted: ${p}`);
  return path.join(HOST_ROOT, p);
}

function assertToken(v, label='value') {
  if (!/^[A-Za-z0-9_.:@/\-[\]]+$/.test(String(v))) throw new Error(`${label} contains unsupported characters`);
  return String(v);
}

function assertNetworkTarget(v, {cidr=false}={}) {
  const x=String(v||'');
  const re=cidr ? /^[A-Za-z0-9_.:%\-[\]\/]+$/ : /^[A-Za-z0-9_.:%\-[\]]+$/;
  if (!x || x.startsWith('-') || !re.test(x)) throw new Error('invalid network target');
  return x;
}

function assertHttpUrl(v) {
  const u=new URL(String(v));
  if(!['http:','https:'].includes(u.protocol)) throw new Error('only http/https URLs are allowed');
  return u.toString();
}

function decodeDockerMux(buf) {
  const chunks=[]; let off=0;
  while(off+8<=buf.length && [0,1,2,3].includes(buf[off])) {
    const len=buf.readUInt32BE(off+4);
    if(off+8+len>buf.length) break;
    chunks.push(buf.subarray(off+8,off+8+len)); off+=8+len;
  }
  return chunks.length && off===buf.length ? Buffer.concat(chunks).toString('utf8') : buf.toString('utf8');
}

function dockerReq(method, apiPath, body=null) {
  return new Promise((resolve,reject) => {
    const data = body == null ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({ socketPath: DOCKER_SOCKET, path: apiPath, method, headers: data ? {'Content-Type':'application/json','Content-Length':data.length} : {} }, res => {
      const chunks=[]; let total=0;
      res.on('data', c => { if(total < 4*1024*1024){ chunks.push(c); total+=c.length; } });
      res.on('end', () => {
        const rawBuf=Buffer.concat(chunks);
        const ct=String(res.headers['content-type']||'');
        const raw=ct.includes('application/vnd.docker.raw-stream') ? decodeDockerMux(rawBuf) : rawBuf.toString('utf8');
        if (res.statusCode >= 400) return reject(new Error(`Docker API ${res.statusCode}: ${raw.slice(0,2000)}`));
        if (ct.includes('application/json')) { try { return resolve(JSON.parse(raw||'null')); } catch {} }
        resolve(raw);
      });
    });
    req.on('error',reject); req.setTimeout(DEFAULT_TIMEOUT,()=>req.destroy(new Error('Docker API timeout')));
    if(data) req.write(data); req.end();
  });
}

async function dockerContainerId(name) {
  return encodeURIComponent(assertToken(name,'container'));
}

async function ssh(target, command, timeout=DEFAULT_TIMEOUT) {
  target=assertToken(target,'target');
  const args=['-F',SSH_CONFIG,'-o','BatchMode=yes','-o','ConnectTimeout=5','--',target,command];
  return run('ssh',args,{timeout});
}

function qsh(v){ return `'${String(v).replaceAll("'", "'\\''")}'`; }

async function readTextFile(p,maxBytes=32768){
  const st=await fsp.stat(p); if(st.size>maxBytes*20){} // permit bounded reads of large logs
  const fh=await fsp.open(p,'r');
  try { const b=Buffer.alloc(Math.min(maxBytes,131072)); const {bytesRead}=await fh.read(b,0,b.length,0); const out=b.subarray(0,bytesRead); if(out.includes(0)) throw new Error('binary file rejected'); return out.toString('utf8'); } finally { await fh.close(); }
}

async function listFiles(root, exts, recursive=false){
  const out=[];
  async function walk(dir,depth){
    for(const ent of await fsp.readdir(dir,{withFileTypes:true})){
      const p=path.join(dir,ent.name);
      if(ent.isDirectory() && recursive && depth<8) await walk(p,depth+1);
      else if(ent.isFile() && exts.has(path.extname(ent.name).toLowerCase())){
        const st=await fsp.stat(p); out.push({path:path.relative(WORKSPACE,p), size:st.size, modified:st.mtime.toISOString()});
      }
      if(out.length>=1000) return;
    }
  }
  await walk(root,0); return out;
}

async function extractText(file,maxChars=60000){
  const ext=path.extname(file).toLowerCase(); let text='';
  if(ext==='.pdf') text=await run('pdftotext',['-layout',file,'-'],{maxBuffer:8*1024*1024});
  else if(['.txt','.md','.csv','.json','.xml','.yaml','.yml','.log'].includes(ext)) text=await readTextFile(file,Math.min(maxChars*2,200000));
  else {
    try { text=await run('pandoc',[file,'-t','plain'],{timeout:60000,maxBuffer:8*1024*1024}); }
    catch(e){
      if(ext==='.docx') text=await run('sh',['-lc',`unzip -p ${qsh(file)} word/document.xml | sed -E 's/<w:tab[^>]*>/\\t/g; s/<\\/w:p>/\\n/g; s/<[^>]+>//g'`]);
      else if(ext==='.pptx') text=await run('sh',['-lc',`for f in $(unzip -Z1 ${qsh(file)} 'ppt/slides/slide*.xml' | sort -V); do unzip -p ${qsh(file)} "$f"; echo; done | sed -E 's/<a:br[^>]*>/\\n/g; s/<\\/a:p>/\\n/g; s/<[^>]+>//g'`]);
      else if(ext==='.xlsx') text=await run('sh',['-lc',`unzip -p ${qsh(file)} xl/sharedStrings.xml 2>/dev/null | sed -E 's/<\\/si>/\\n/g; s/<[^>]+>//g'`]);
      else throw e;
    }
  }
  return text.slice(0,Math.min(maxChars,200000));
}

async function callTool(name,a={}){
  switch(name){
    case 'docker_list_containers': {
      const includeAll=a.all===true; const rows=await dockerReq('GET',`/containers/json?all=${includeAll?1:0}`);
      const containers=(Array.isArray(rows)?rows:[]).map(c=>({
        id:String(c.Id||'').slice(0,12),
        name:(Array.isArray(c.Names)&&c.Names[0]?String(c.Names[0]).replace(/^\//,''):null),
        image:c.Image||null,
        state:c.State||null,
        status:c.Status||null,
        health:/\((healthy|unhealthy|health: starting)\)/i.exec(String(c.Status||''))?.[1]||null,
        ports:(c.Ports||[]).map(p=>({ip:p.IP||null,private_port:p.PrivatePort||null,public_port:p.PublicPort||null,type:p.Type||null})),
        networks:Object.keys(c.NetworkSettings?.Networks||{}),
        compose_project:c.Labels?.['com.docker.compose.project']||null,
        compose_service:c.Labels?.['com.docker.compose.service']||null,
      }));
      return {count:containers.length,all:includeAll,containers};
    }
    case 'docker_inspect_container': return dockerReq('GET',`/containers/${await dockerContainerId(a.container)}/json`);
    case 'docker_container_logs': {
      const tail=Math.max(1,Math.min(5000,Number(a.tail||200))); const since=a.since?`&since=${encodeURIComponent(a.since)}`:'';
      return dockerReq('GET',`/containers/${await dockerContainerId(a.container)}/logs?stdout=1&stderr=1&timestamps=1&tail=${tail}${since}`);
    }
    case 'docker_container_stats': return dockerReq('GET',`/containers/${await dockerContainerId(a.container)}/stats?stream=false`);
    case 'docker_list_images': return dockerReq('GET','/images/json?all=1');
    case 'docker_inspect_image': return dockerReq('GET',`/images/${encodeURIComponent(assertToken(a.image,'image'))}/json`);
    case 'docker_list_networks': return dockerReq('GET','/networks');
    case 'docker_inspect_network': return dockerReq('GET',`/networks/${encodeURIComponent(assertToken(a.network,'network'))}`);
    case 'docker_list_volumes': return dockerReq('GET','/volumes');
    case 'docker_inspect_volume': return dockerReq('GET',`/volumes/${encodeURIComponent(assertToken(a.volume,'volume'))}`);
    case 'docker_exec': {
      if(!DOCKER_ALLOW_EXEC) throw new Error('Docker exec disabled; set DOCKER_ALLOW_EXEC=true to enable');
      const id=await dockerContainerId(a.container);
      const created=await dockerReq('POST',`/containers/${id}/exec`,{AttachStdout:true,AttachStderr:true,Tty:true,Cmd:['/bin/sh','-lc',String(a.command)]});
      const seconds=Math.max(1,Math.min(300,Number(a.timeout||30)));
      return run('curl',['-sS','--max-time',String(seconds),'--unix-socket',DOCKER_SOCKET,'-H','Content-Type: application/json','-X','POST','--data','{"Detach":false,"Tty":true}',`http://localhost/exec/${created.Id}/start`],{timeout:(seconds+2)*1000,maxBuffer:4*1024*1024});
    }
    case 'docker_container_action': {
      if(!DOCKER_ALLOW_WRITE) throw new Error('Docker mutations disabled; set DOCKER_ALLOW_WRITE=true to enable');
      const id=await dockerContainerId(a.container), act=a.action; let qs=''; if(['stop','restart'].includes(act)&&a.timeout!=null) qs=`?t=${Math.max(0,Math.min(300,Number(a.timeout)))}`;
      await dockerReq('POST',`/containers/${id}/${act}${qs}`); return {ok:true,container:a.container,action:act};
    }
    case 'docker_remove_container': if(!DOCKER_ALLOW_WRITE) throw new Error('Docker mutations disabled; set DOCKER_ALLOW_WRITE=true to enable'); else {await dockerReq('DELETE',`/containers/${await dockerContainerId(a.container)}?force=${a.force?1:0}`); return {ok:true};}
    case 'docker_remove_image': if(!DOCKER_ALLOW_WRITE) throw new Error('Docker mutations disabled; set DOCKER_ALLOW_WRITE=true to enable'); else return dockerReq('DELETE',`/images/${encodeURIComponent(assertToken(a.image,'image'))}?force=${a.force?1:0}`);


    case 'host_snapshot': {
      const [osr,hostName,up,load,mem,cpu,df]=await Promise.all([
        readTextFile(hostPath('/etc/os-release'),16384).catch(()=>''), readTextFile(hostPath('/etc/hostname'),1024).catch(()=>os.hostname()), readTextFile(hostPath('/proc/uptime'),1024), readTextFile(hostPath('/proc/loadavg'),1024), readTextFile(hostPath('/proc/meminfo'),16384), readTextFile(hostPath('/proc/cpuinfo'),65536), run('df',['-hP',HOST_ROOT])
      ]);
      const model=(cpu.match(/^model name\s*:\s*(.+)$/m)||cpu.match(/^Hardware\s*:\s*(.+)$/m)||[])[1];
      const cpus=(cpu.match(/^processor\s*:/gm)||[]).length; const kv=Object.fromEntries(mem.split('\n').filter(x=>x.includes(':')).map(x=>x.split(/:\s*/,2)));
      return {hostname:hostName.trim(), os_release:osr.trim(), uptime_seconds:Number(up.split(/\s+/)[0]), load_average:load.trim(), cpu:{model,logical_processors:cpus}, memory:{MemTotal:kv.MemTotal,MemAvailable:kv.MemAvailable,SwapTotal:kv.SwapTotal,SwapFree:kv.SwapFree}, host_root_df:df};
    }
    case 'host_cpu_info': { const cpu=await readTextFile(hostPath('/proc/cpuinfo'),131072); const stat=await readTextFile(hostPath('/proc/stat'),65536); const load=await readTextFile(hostPath('/proc/loadavg'),1024); return {load:load.trim(),cpuinfo:cpu,stat:stat}; }
    case 'host_memory_info': return readTextFile(hostPath('/proc/meminfo'),65536);
    case 'host_processes': {
      const dir=hostPath('/proc'); const pids=(await fsp.readdir(dir)).filter(x=>/^\d+$/.test(x)); const rows=[];
      for(const pid of pids){ try { const status=await readTextFile(path.join(dir,pid,'status'),16384); const stat=await readTextFile(path.join(dir,pid,'stat'),8192); const cmd=(await readTextFile(path.join(dir,pid,'cmdline'),8192)).replaceAll('\0',' ').trim(); const get=k=>(status.match(new RegExp(`^${k}:\\s*(.+)$`,'m'))||[])[1]||''; const parts=stat.split(' '); rows.push({pid:Number(pid),name:get('Name'),state:get('State'),rss:get('VmRSS'),threads:get('Threads'),cpu_ticks:Number(parts[13]||0)+Number(parts[14]||0),cmdline:cmd}); } catch{} }
      const sort=a.sort_by||'rss'; const rss=x=>Number((x.rss.match(/\d+/)||[0])[0]); rows.sort((x,y)=>sort==='pid'?x.pid-y.pid:sort==='name'?x.name.localeCompare(y.name):sort==='cpu'?y.cpu_ticks-x.cpu_ticks:rss(y)-rss(x)); return rows.slice(0,Math.max(1,Math.min(500,Number(a.limit||80))));
    }
    case 'host_process_info': { const base=hostPath(`/proc/${Number(a.pid)}`); const out={pid:Number(a.pid)}; for(const f of ['status','stat','cmdline','environ','limits','cgroup']){ try { let v=await readTextFile(path.join(base,f),65536); if(f==='cmdline'||f==='environ') v=v.replaceAll('\0','\n'); if(f==='environ') v=v.split('\n').filter(x=>/^(PATH|HOME|USER|SHELL|LANG|LC_|TERM|XDG_|WAYLAND_DISPLAY|DISPLAY)=/.test(x)).join('\n'); out[f]=v; }catch{} } try{out.exe=await fsp.readlink(path.join(base,'exe'));}catch{} try{out.open_files=(await fsp.readdir(path.join(base,'fd'))).length;}catch{} return out; }
    case 'host_network_info': return {interfaces:await readTextFile(hostPath('/proc/net/dev'),65536), routes:await readTextFile(hostPath('/proc/net/route'),65536), arp:await readTextFile(hostPath('/proc/net/arp'),65536).catch(()=>''), resolv_conf:await readTextFile(hostPath('/etc/resolv.conf'),16384).catch(()=>'')};
    case 'host_disk_usage': return run('df',['-hPT',HOST_ROOT]);
    case 'host_read_file': return readTextFile(hostPath(a.path),Math.max(1,Math.min(131072,Number(a.max_bytes||32768))));

    case 'network_dns_lookup': return run('dig',['+noall','+answer',assertNetworkTarget(a.name),a.type||'A']);
    case 'network_ping': return run('ping',['-n','-c',String(Math.max(1,Math.min(20,Number(a.count||4)))),'-W',String(Math.max(1,Math.min(10,Number(a.timeout||2)))),assertNetworkTarget(a.host)],{timeout:60000});
    case 'network_trace_route': return run('traceroute',['-n','-m',String(Math.max(1,Math.min(64,Number(a.max_hops||20)))),assertNetworkTarget(a.host)],{timeout:60000});
    case 'network_http_probe': { const args=['-sS','-L','--max-time','15','-o',a.body&&a.method!=='HEAD'?'-':'/dev/null','-w','\nHTTP %{http_code}\nremote=%{remote_ip}:%{remote_port}\ndns=%{time_namelookup}\nconnect=%{time_connect}\ntls=%{time_appconnect}\nttfb=%{time_starttransfer}\ntotal=%{time_total}\nurl=%{url_effective}\n']; if((a.method||'GET')==='HEAD') args.splice(1,0,'-I'); args.push(assertHttpUrl(a.url)); args.splice(args.length-1,0,'-D','-'); return run('curl',args,{timeout:20000,maxBuffer:2*1024*1024}); }
    case 'network_port_check': return run('nc',['-vz','-w',String(Math.max(1,Math.min(30,Number(a.timeout||3)))),assertNetworkTarget(a.host),String(Number(a.port))],{timeout:35000});
    case 'network_scan_ports': { const args=['-Pn','-T4','--max-retries','1','--host-timeout','45s']; if(a.ports) args.push('-p',a.ports); if(a.service_detection) args.push('-sV','--version-light'); args.push(assertNetworkTarget(a.target,{cidr:true})); return run('nmap',args,{timeout:60000,maxBuffer:2*1024*1024}); }
    case 'network_interfaces': return run('sh',['-lc','ip -brief address; echo "--- routes ---"; ip route; echo "--- neighbors ---"; ip neigh']);

    case 'openwrt_status': return ssh(a.target,`echo '--- release ---'; cat /etc/openwrt_release 2>/dev/null || cat /etc/os-release; echo '--- uptime/load ---'; uptime; echo '--- memory ---'; free 2>/dev/null || cat /proc/meminfo; echo '--- mounts ---'; df -h; echo '--- board ---'; ubus call system board 2>/dev/null; echo '--- interfaces ---'; ubus call network.interface dump 2>/dev/null; echo '--- routes ---'; ip route 2>/dev/null || route -n`);
    case 'openwrt_uci_show': return ssh(a.target,`uci show${a.package?' '+qsh(assertToken(a.package,'package')):''}`);
    case 'openwrt_uci_get': return ssh(a.target,`uci -q get ${qsh(a.key)}`);
    case 'openwrt_ubus_call': { const js=a.args||'{}'; JSON.parse(js); return ssh(a.target,`ubus call ${qsh(assertToken(a.object,'object'))} ${qsh(assertToken(a.method,'method'))} ${qsh(js)}`); }
    case 'openwrt_logread': { const n=Math.max(1,Math.min(3000,Number(a.lines||200))); const filter=a.filter?` | grep -i -- ${qsh(a.filter)}`:''; return ssh(a.target,`logread | tail -n ${n}${filter}`); }
    case 'openwrt_wifi_status': return ssh(a.target,`echo '--- ubus wireless ---'; ubus call network.wireless status 2>/dev/null; echo '--- iwinfo ---'; for i in $(iwinfo 2>/dev/null | awk '/ESSID:/{print $1}'); do iwinfo "$i" info; iwinfo "$i" assoclist; done`);
    case 'openwrt_clients': return ssh(a.target,`echo '--- DHCP leases ---'; cat /tmp/dhcp.leases 2>/dev/null; echo '--- neighbors ---'; ip neigh 2>/dev/null || arp -an 2>/dev/null; echo '--- wifi associations ---'; for i in $(iwinfo 2>/dev/null | awk '/ESSID:/{print $1}'); do echo "[$i]"; iwinfo "$i" assoclist; done`);
    case 'openwrt_package_query': { const f=a.query?` | grep -i -- ${qsh(a.query)}`:''; return ssh(a.target,`${a.mode==='search'?'opkg list':'opkg list-installed'}${f}`); }
    case 'openwrt_service_action': if(!OPENWRT_ALLOW_WRITE) throw new Error('OpenWrt mutations disabled; set OPENWRT_ALLOW_WRITE=true to enable'); else return ssh(a.target,`/etc/init.d/${assertToken(a.service,'service')} ${assertToken(a.action,'action')}`);
    case 'openwrt_uci_set': { if(!OPENWRT_ALLOW_WRITE) throw new Error('OpenWrt mutations disabled; set OPENWRT_ALLOW_WRITE=true to enable'); const key=assertToken(a.key,'key'); const pkg=key.split('.')[0]; return ssh(a.target,`uci set ${qsh(`${key}=${a.value}`)}${a.commit?`; uci commit ${qsh(pkg)}`:''}`); }

    case 'image_list': return listFiles(safeWorkspace(a.directory||'.',{mustExist:true}),new Set(['.png','.jpg','.jpeg','.webp','.gif','.tif','.tiff','.bmp','.svg']),!!a.recursive);
    case 'image_info': return run('identify',['-verbose',safeWorkspace(a.path,{mustExist:true})]);
    case 'image_metadata': return run('exiftool',['-G1','-a','-s',safeWorkspace(a.path,{mustExist:true})]);
    case 'image_resize': { const i=safeWorkspace(a.input,{mustExist:true}),o=safeWorkspace(a.output); await fsp.mkdir(path.dirname(o),{recursive:true}); return run('convert',[i,'-resize',a.geometry,o],{timeout:60000}); }
    case 'image_crop': { const i=safeWorkspace(a.input,{mustExist:true}),o=safeWorkspace(a.output); await fsp.mkdir(path.dirname(o),{recursive:true}); return run('convert',[i,'-crop',`${Number(a.width)}x${Number(a.height)}+${Number(a.x||0)}+${Number(a.y||0)}`,'+repage',o],{timeout:60000}); }
    case 'image_convert': { const i=safeWorkspace(a.input,{mustExist:true}),o=safeWorkspace(a.output); await fsp.mkdir(path.dirname(o),{recursive:true}); const args=[i]; if(a.quality!=null) args.push('-quality',String(Number(a.quality))); args.push(o); return run('convert',args,{timeout:60000}); }
    case 'image_compare': { const l=safeWorkspace(a.left,{mustExist:true}),r=safeWorkspace(a.right,{mustExist:true}); const args=['-metric','RMSE',l,r]; if(a.diff_output){const o=safeWorkspace(a.diff_output); await fsp.mkdir(path.dirname(o),{recursive:true}); args.push(o);} else args.push('null:'); try{const z=await execFileAsync('compare',args,{timeout:60000,maxBuffer:4*1024*1024}); return {metric:(z.stderr||z.stdout||'0').trim(),identical:true,diff_output:a.diff_output||null};}catch(e){if(e.code===1) return {metric:String(e.stderr||e.stdout||'').trim(),identical:false,diff_output:a.diff_output||null}; throw e;} }
    case 'image_thumbnail': { const i=safeWorkspace(a.input,{mustExist:true}),o=safeWorkspace(a.output); await fsp.mkdir(path.dirname(o),{recursive:true}); const geom=`${Number(a.width)}x${Number(a.height)}${a.enlarge?'':'>'}`; return run('convert',[i,'-thumbnail',geom,o],{timeout:60000}); }

    case 'document_list': return listFiles(safeWorkspace(a.directory||'.',{mustExist:true}),new Set(['.pdf','.docx','.odt','.rtf','.html','.htm','.md','.txt','.csv','.xlsx','.pptx','.epub','.json','.xml','.yaml','.yml']),!!a.recursive);
    case 'document_info': { const p=safeWorkspace(a.path,{mustExist:true}); const st=await fsp.stat(p); const type=await run('file',['-b','--mime-type',p]); const out={path:a.path,size:st.size,modified:st.mtime.toISOString(),mime:type.trim()}; if(path.extname(p).toLowerCase()==='.pdf'){ try{out.pdfinfo=await run('pdfinfo',[p]);}catch{}} return out; }
    case 'document_extract_text': return extractText(safeWorkspace(a.path,{mustExist:true}),Math.max(100,Math.min(200000,Number(a.max_chars||60000))));
    case 'document_search_text': { const text=await extractText(safeWorkspace(a.path,{mustExist:true}),200000); const lines=text.split('\n'); const re=a.regex?new RegExp(a.query,'i'):null; const ctx=Math.max(0,Math.min(10,Number(a.context??2))), max=Math.max(1,Math.min(200,Number(a.max_matches||50))); const hits=[]; for(let i=0;i<lines.length&&hits.length<max;i++){ if(a.regex?re.test(lines[i]):lines[i].toLowerCase().includes(String(a.query).toLowerCase())) hits.push({line:i+1,text:lines.slice(Math.max(0,i-ctx),Math.min(lines.length,i+ctx+1)).join('\n')}); } return hits; }
    case 'document_convert': { const i=safeWorkspace(a.input,{mustExist:true}),o=safeWorkspace(a.output); await fsp.mkdir(path.dirname(o),{recursive:true}); const args=[i,'-o',o]; if(a.to) args.push('-t',a.to); await run('pandoc',args,{timeout:120000,maxBuffer:4*1024*1024}); return {ok:true,output:path.relative(WORKSPACE,o)}; }
    case 'document_render_pdf_page': { const i=safeWorkspace(a.input,{mustExist:true}),o=safeWorkspace(a.output); await fsp.mkdir(path.dirname(o),{recursive:true}); const base=o.toLowerCase().endsWith('.png')?o.slice(0,-4):o; await run('pdftoppm',['-f',String(Number(a.page)),'-singlefile','-png','-r',String(Number(a.dpi||144)),i,base],{timeout:120000}); const actual=base+'.png'; if(actual!==o&&fs.existsSync(actual)) await fsp.rename(actual,o); return {ok:true,output:path.relative(WORKSPACE,o)}; }
  }
  throw new Error(`unknown tool: ${name}`);
}

function response(id,result){ process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,result})+'\n'); }
function errorResponse(id,code,message,data){ process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,error:{code,message,...(data?{data}: {})}})+'\n'); }

let input='';
process.stdin.setEncoding('utf8');
process.stdin.on('data',chunk=>{ input+=chunk; let idx; while((idx=input.indexOf('\n'))>=0){ const line=input.slice(0,idx).trim(); input=input.slice(idx+1); if(line) handle(line); } });

async function handle(line){
  let msg; try{msg=JSON.parse(line);}catch{return;}
  if(msg.method==='notifications/initialized' || msg.method==='notifications/cancelled') return;
  if(msg.id==null) return;
  try{
    if(msg.method==='initialize') return response(msg.id,{protocolVersion:msg.params?.protocolVersion||'2025-06-18',capabilities:{tools:{listChanged:false}},serverInfo:{name:'local-system-tools',version:'1.0.0'}});
    if(msg.method==='ping') return response(msg.id,{});
    if(msg.method==='tools/list') return response(msg.id,{tools:TOOLS});
    if(msg.method==='tools/call'){
      const name=msg.params?.name,args=msg.params?.arguments||{};
      if(!toolMap.has(name)) throw new Error(`unknown tool: ${name}`);
      try{ const out=await callTool(name,args); return response(msg.id,{content:[{type:'text',text:clip(out)}],isError:false}); }
      catch(e){ return response(msg.id,{content:[{type:'text',text:clip(e?.stack||String(e))}],isError:true}); }
    }
    return errorResponse(msg.id,-32601,`Method not found: ${msg.method}`);
  }catch(e){ return errorResponse(msg.id,-32603,e?.message||String(e)); }
}
