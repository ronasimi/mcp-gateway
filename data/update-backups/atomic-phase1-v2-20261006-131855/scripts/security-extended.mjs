import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { JobManager, confinedPath } from './security-runtime.mjs';

const text = (description, extra = {}) => ({ type: 'string', description, ...extra });
const integer = (description, minimum, maximum) => ({ type: 'integer', description, minimum, maximum });
const schema = (description, properties = {}, required = []) => ({ type: 'object', description, properties, required, additionalProperties: false });
const tool = (name, description, properties, required = [], annotations = {}) => ({ name, description,
  inputSchema: schema(description, properties, required),
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false, ...annotations } });
const active = { readOnlyHint: false, idempotentHint: false, openWorldHint: true };
const seconds = integer('Deadline in seconds; defaults vary by tool, maximum 300.', 5, 300);
const file = text('Workspace-relative input file.');

export const EXTENDED_TOOLS = [
  tool('status', 'Inspect installed security binaries, host-recon helper availability, Firecrawl configuration status, job capacity, and execution visibility without starting scans.', {}),
  tool('firecrawl_scrape', 'Firecrawl CLI: scrape one HTTP/HTTPS URL to clean Markdown using the configured Firecrawl backend. API credentials remain server-side.', { url: text('URL to scrape.'), max_chars: integer('Maximum Markdown characters returned; default 12000.', 100, 20000) }, ['url'], { openWorldHint: true }),
  tool('firecrawl_map', 'Firecrawl CLI: map website URLs with JSON output and a bounded result limit using the configured backend.', { url: text('Website URL to map.'), limit: integer('Maximum discovered URLs; default 100.', 1, 500) }, ['url'], { openWorldHint: true }),
  tool('subdomain_enum', 'Passive Subfinder OSINT: enumerate subdomains from public sources with JSONL output, bounded runtime and rate. Does not run active DNS enumeration.', { domain: text('Domain whose subdomains are requested.'), timeout_seconds: seconds, max_results: integer('Maximum names returned; default 100.', 1, 500) }, ['domain'], { openWorldHint: true }),
  tool('exploit_search', 'Searchsploit: search the local Exploit-DB catalogue for service versions or CVEs and return compact JSON records. This operation does not execute exploits.', { query: text('Search words, service version or CVE.', { minLength: 1, maxLength: 200 }), limit: integer('Maximum records returned; default 20.', 1, 100) }, ['query']),
  tool('exploit_source', 'Read a bounded excerpt of an Exploit-DB source by EDB ID for review; never executes the source.', { edb_id: integer('Numeric Exploit-DB ID.', 1, 999999), start_line: integer('First source line, one-based; default 1.', 1, 100000), max_lines: integer('Maximum source lines returned; default 120.', 1, 300) }, ['edb_id']),
  tool('sqlmap', 'Run bounded sqlmap SQL-injection testing or database-name enumeration against an authorized URL. Always uses --batch and disables interactive prompts and redirects.', { url: text('Authorized URL including the parameter to test.'), parameter: text('Specific GET/POST parameter name, if known.', { maxLength: 100 }), data: text('Optional URL-encoded POST body.', { maxLength: 4096 }), action: text('Default detect; database names require enumerate_databases.', { enum: ['detect', 'current_database', 'enumerate_databases'] }), timeout_seconds: seconds }, ['url'], active),
  tool('metasploit_info', 'Inspect Metasploit module help and options through a noninteractive msfconsole resource script; does not launch the module.', { module: text('Full auxiliary/scanner/... or exploit/... module path.') }, ['module']),
  tool('metasploit_run', 'Run or check one Metasploit module on an authorized target using a generated resource script. Returns a background job ID; poll with job_status.', { module: text('Full auxiliary/scanner/... or exploit/... module path.'), target: text('One authorized target IP or hostname, never a range.'), action: text('Default check. run explicitly launches the module.', { enum: ['check', 'run'] }), options: { type: 'object', description: 'Module settings such as RPORT, TARGETURI, PAYLOAD, LHOST or LPORT; RHOST/RHOSTS are supplied from target.', additionalProperties: text('Single console-safe setting value.', { maxLength: 512 }) }, timeout_seconds: seconds }, ['module', 'target'], { ...active, destructiveHint: true }),
  tool('listener_start', 'Start a bounded Netcat or Socat TCP listener as a background job for an authorized lab callback. Poll output, send input or stop through job tools.', { engine: text('Listener implementation; default nc.', { enum: ['nc', 'socat'] }), port: integer('Published container port, 4444 through 4453.', 4444, 4453), timeout_seconds: seconds }, ['port'], active),
  tool('job_status', 'Read bounded output and lifecycle state from a security listener or Metasploit job. Supply next_offset from the previous result to avoid repeated output.', { job_id: text('ID returned by a background tool.'), offset: integer('Absolute output byte offset; default 0.', 0, 2147483647), max_bytes: integer('Maximum output bytes; default 8000.', 128, 12000) }, ['job_id']),
  tool('job_send', 'Send bounded text to an existing Netcat or Socat listener connection, including a newline when needed. Input goes only to the selected job.', { job_id: text('Listener job ID.'), input: text('Text to send, including any required newline.', { maxLength: 4096 }) }, ['job_id', 'input'], { ...active, destructiveHint: true }),
  tool('job_stop', 'Stop a security background job and its child processes, closing any listener ports owned by that job.', { job_id: text('ID returned by a background tool.') }, ['job_id'], { readOnlyHint: false, idempotentHint: true }),
  tool('jq', 'Filter a workspace JSON or JSONL log with jq before returning records. Runs one noninteractive filter with bounded time and output; input files stay local.', { path: file, filter: text('jq expression; default .', { maxLength: 4096 }), limit: integer('Maximum output JSON records; default 100.', 1, 500) }, ['path']),
  tool('pcap_analyze', 'Analyze a saved PCAP: protocol summary, endpoint conversations, or selected packet fields. All views use offline Tshark.', { path: file, view:text('Analysis view; default summary.',{enum:['summary','conversations','fields']}), protocol:text('Conversation type; default ip.',{enum:['ip','ipv6','tcp','udp']}), display_filter: text('Wireshark display filter such as dns or tcp.flags.syn == 1.', { maxLength: 1000 }), fields: { type: 'array', description: 'Fields to extract; default timestamp, source, destination, ports and protocol.', items: text('Tshark field such as ip.src or dns.qry.name.'), minItems: 1, maxItems: 16 }, packet_limit: integer('Maximum packets to examine, before display filtering; default 1000.', 1, 20000), max_rows: integer('Maximum matching rows returned; default 100.', 1, 300) }, ['path']),
  tool('suricata_test_rules', 'Validate workspace Suricata rules with -T, optionally replay them exclusively against a PCAP and report matched signatures, packet counts and hit rate.', { rules: text('Workspace-relative .rules file.'), pcap: text('Optional workspace-relative PCAP/PCAPNG.'), max_alerts: integer('Maximum alert records returned; default 100.', 1, 300) }, ['rules'], { readOnlyHint: false }),
  tool('osquery', 'Run one read-only SELECT or WITH query through osqueryi --json with extensions disabled. Visibility is the security container, not the host process/network namespace.', { query: text('SQL, e.g. SELECT * FROM listening_ports;', { maxLength: 8192 }), limit: integer('Maximum rows returned; default 100.', 1, 500) }, ['query']),
  tool('binary_analyze', 'Analyze a workspace binary with Radare2 in noninteractive read-only sandbox mode. Returns JSON for metadata, imports, exports, strings, functions or disassembly without executing it.', { path: file, operation: text('Analysis operation; default info.', { enum: ['info', 'imports', 'exports', 'strings', 'functions', 'disassemble'] }), address: text('Disassembly virtual address as decimal or 0x hex; default entry0.'), count: integer('Maximum disassembly instructions; default 64.', 1, 256) }, ['path']),
];

export function createExtendedSecurity(ctx) {
  const { runStatus, safeWorkspace, assertAuthorizedTarget, assertAuthorizedUrl } = ctx;
  const jobs = new JobManager();
  const binaries = ['nmap', 'dig', 'ip', 'iw', 'nmcli', 'airodump-ng', 'avahi-browse', 'dot', 'ethtool', 'firecrawl', 'ffuf', 'subfinder', 'searchsploit', 'sqlmap', 'msfconsole', 'nc', 'socat', 'jq', 'tshark', 'suricata', 'osqueryi', 'yara', 'r2'];
  const stripAnsi = s => String(s).replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
  function parsed(result) {
    if (result.code !== 0) throw new Error(`command failed (${result.code}): ${result.stderr.slice(0,2000) || result.stdout.slice(0,2000)}`);
    try { return JSON.parse(result.stdout); } catch { throw new Error('tool returned invalid or incomplete JSON'); }
  }
  function moduleName(value) {
    if (!/^(auxiliary\/scanner|exploit)\/[a-zA-Z0-9_/-]+$/.test(value) || value.includes('..')) throw new Error('invalid Metasploit module path');
    return value;
  }
  function setting(value) {
    if (!/^[a-zA-Z0-9_./:@%?=&,+ -]+$/.test(value) || value.includes('\n') || value.startsWith('-')) throw new Error('unsupported Metasploit option value');
    return value;
  }
  async function firecrawlUrl(value) {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('expected an HTTP/HTTPS URL without embedded credentials');
    // Backend credentials are never accepted through model-facing arguments.
    const api = process.env.FIRECRAWL_API_URL || 'https://api.firecrawl.dev';
    if (!process.env.FIRECRAWL_API_KEY && api === 'https://api.firecrawl.dev') throw new Error('configure FIRECRAWL_API_KEY server-side, or set a self-hosted FIRECRAWL_API_URL');
    return url.toString();
  }
  async function resource(lines, options = {}) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'msf-'));
    const filename = path.join(dir, 'task.rc');
    await fs.writeFile(filename, lines.join('\n') + '\nexit -y\n', { mode: 0o600 });
    const cleanup = () => fs.rm(dir, { recursive: true, force: true });
    const args = ['-q', '-r', filename];
    let started = false;
    try {
      if (options.background) {
        const job = await jobs.start('msfconsole', args, { label: options.label, timeout: options.timeout, cleanup });
        started = true; return job;
      }
      const result = await runStatus('msfconsole', args, { timeout: 120000 });
      return { exit_code: result.code, complete: result.code === 0, output: stripAnsi(result.stdout + result.stderr).slice(0,16000) };
    } finally { if (!started) await cleanup(); }
  }
  async function call(name, a) {
    switch (name) {
      case 'status': {
        const installed = {};
        for (const binary of binaries) {
          installed[binary] = false;
          for (const dir of (process.env.PATH || '').split(path.delimiter)) {
            try { await fs.access(path.join(dir, binary), 1); installed[binary] = true; break; } catch {}
          }
        }
        let host_recon_helper=false; const helper=process.env.SECURITY_HOST_RECON_SOCKET;
        if(helper){try{await fs.access(helper);host_recon_helper=true;}catch{}}
        return { installed, firecrawl: { backend: process.env.FIRECRAWL_API_URL || 'https://api.firecrawl.dev', credential_configured: Boolean(process.env.FIRECRAWL_API_KEY) },
          host_recon_helper:{configured:Boolean(helper),available:host_recon_helper,socket:helper||null},
          visibility: host_recon_helper ? 'high-level network recon delegates through a local Unix socket to the host helper; other tools retain their documented container/target scope' : 'container process/network/filesystem namespace; host files mounted separately at /host', max_background_jobs: jobs.maxJobs, running_jobs: [...jobs.jobs.values()].filter(j => j.status === 'running').map(j => j.id) };
      }
      case 'firecrawl_scrape': {
        const url = await firecrawlUrl(a.url);
        const r = await runStatus('firecrawl', ['scrape', url, '--format', 'markdown', '--only-main-content'], { timeout: 90000 });
        if (r.code !== 0) throw new Error(`Firecrawl failed (${r.code}); check the backend and server-side credentials`);
        const limit = a.max_chars ?? 12000;
        return { url, markdown: r.stdout.slice(0, limit), total_chars: r.stdout.length, truncated: r.stdout.length > limit, complete: true };
      }
      case 'firecrawl_map': {
        const url = await firecrawlUrl(a.url), limit = a.limit ?? 100;
        const j = parsed(await runStatus('firecrawl', ['map', url, '--json', '--limit', String(limit)], { timeout: 90000 }));
        if (j.success === false) throw new Error('Firecrawl map reported failure');
        const links = j.links ?? j.data?.links ?? (Array.isArray(j) ? j : null);
        if (!Array.isArray(links)) throw new Error('Firecrawl map response lacks a links array');
        return { url, links: links.slice(0, limit), returned: Math.min(limit, links.length), limit, complete: true, exhaustive: false };
      }
      case 'subdomain_enum': {
        const domain = a.domain.toLowerCase().replace(/\.$/, '');
        if (domain.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) throw new Error('invalid domain');
        const r = await runStatus('subfinder', ['-d', domain, '-silent', '-json', '-rl', '10', '-timeout', '10', '-max-time', String(Math.ceil((a.timeout_seconds ?? 120) / 60))], { timeout: (a.timeout_seconds ?? 120) * 1000 });
        const names = new Set(); let invalid = 0;
        for (const line of r.stdout.split('\n').filter(Boolean)) {
          try { const host = JSON.parse(line).host; if (typeof host === 'string' && (host === domain || host.endsWith('.' + domain))) names.add(host); } catch { invalid++; }
        }
        const list = [...names].sort(), limit = a.max_results ?? 100;
        return { domain, count: list.length, subdomains: list.slice(0, limit), truncated: list.length > limit, complete: r.code === 0 && !invalid, exhaustive: false, exit_code: r.code, errors: r.stderr.slice(0,1000) };
      }
      case 'exploit_search': {
        const words = a.query.trim().split(/\s+/);
        if (words.some(w => w.startsWith('-'))) throw new Error('search words must not be CLI options');
        const j = parsed(await runStatus('searchsploit', ['--json', ...words], { timeout: 30000 }));
        const rows = [...(j.RESULTS_EXPLOIT ?? []), ...(j.RESULTS_SHELLCODE ?? [])];
        return { query: a.query, count: rows.length, results: rows.slice(0,a.limit ?? 20), truncated: rows.length > (a.limit ?? 20), complete: true };
      }
      case 'exploit_source': {
        const r = await runStatus('searchsploit', ['--disable-colour', '-p', String(a.edb_id)], { timeout: 30000 });
        const found = /^\s*Path:\s*(.+)$/m.exec(stripAnsi(r.stdout))?.[1]?.trim();
        if (r.code !== 0 || !found) throw new Error('Exploit-DB ID not found');
        const source = confinedPath('/opt/exploitdb', found, { mustExist: true });
        const lines = (await fs.readFile(source, 'utf8')).split('\n'), start = (a.start_line ?? 1) - 1, end = start + (a.max_lines ?? 120);
        return { edb_id: a.edb_id, path: path.relative('/opt/exploitdb', source), start_line: start + 1, total_lines: lines.length, source: lines.slice(start,end).join('\n'), has_more: end < lines.length };
      }
      case 'sqlmap': {
        const url = await assertAuthorizedUrl(a.url);
        const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sqlmap-'));
        try {
          const args = ['-u', url, '--batch', '--disable-coloring', '--ignore-redirects', '--threads=1', '--level=1', '--risk=1', '--timeout=8', '--retries=0', '--output-dir=' + dir];
          if (a.parameter) { if (!/^[a-zA-Z0-9_.\[\]-]+$/.test(a.parameter) || a.parameter.startsWith('-')) throw new Error('invalid parameter name'); args.push('-p',a.parameter); }
          if (a.data) args.push('--data=' + a.data);
          if (a.action === 'current_database') args.push('--current-db');
          if (a.action === 'enumerate_databases') args.push('--dbs');
          const r = await runStatus('sqlmap', args, { timeout: (a.timeout_seconds ?? 120) * 1000 });
          return { url, action: a.action ?? 'detect', exit_code: r.code, complete: r.code === 0 && !/\[CRITICAL\]/.test(r.stdout + r.stderr), report: stripAnsi(r.stdout + r.stderr) };
        } finally { await fs.rm(dir, { recursive: true, force: true }); }
      }
      case 'metasploit_info': return resource(['use ' + moduleName(a.module), 'info', 'show options']);
      case 'metasploit_run': {
        const target = await assertAuthorizedTarget(a.target), module = moduleName(a.module);
        const lines = ['use ' + module, 'set RHOSTS ' + setting(target), 'set RHOST ' + setting(target)];
        for (const [key, value] of Object.entries(a.options ?? {})) {
          if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(key) || ['RHOST', 'RHOSTS', 'WORKSPACE'].includes(key)) throw new Error('unsupported or reserved Metasploit option');
          if (key === 'LHOST') await assertAuthorizedTarget(value);
          if (key === 'LPORT' && (!/^\d+$/.test(value) || +value < 4444 || +value > 4453)) throw new Error('LPORT must be in published range 4444-4453');
          lines.push(`set ${key} ${setting(value)}`);
        }
        lines.push(a.action === 'run' ? 'run -z' : 'check');
        return resource(lines, { background: true, timeout: (a.timeout_seconds ?? 120) * 1000, label: module });
      }
      case 'listener_start': {
        await assertAuthorizedTarget('127.0.0.1');
        const engine = a.engine ?? 'nc';
        const args = engine === 'nc' ? ['-l', '-n', '-v', '-s', '0.0.0.0', String(a.port)] : ['-d', '-d', `TCP4-LISTEN:${a.port},bind=0.0.0.0,reuseaddr`, 'STDIO'];
        return jobs.start(engine, args, { timeout: (a.timeout_seconds ?? 120) * 1000, label: `${engine} listener:${a.port}`, interactive: true });
      }
      case 'job_status': return jobs.status(a.job_id, a.offset ?? 0, a.max_bytes ?? 8000);
      case 'job_send': return jobs.send(a.job_id, a.input);
      case 'job_stop': return jobs.stop(a.job_id);
      case 'jq': {
        const p = safeWorkspace(a.path, { mustExist: true }), limit = a.limit ?? 100;
        // -n + inputs keeps JSONL streaming; limit counts across the whole file.
        const filter = `limit(${limit + 1}; inputs | (${a.filter ?? '.'}))`;
        const r = await runStatus('jq', ['-c', '-n', '--', filter, p], { timeout: 30000, maxBuffer: 4 * 1024 * 1024, env: { FIRECRAWL_API_KEY: '' } });
        if (r.code !== 0) throw new Error(`jq failed (${r.code}): ${r.stderr.slice(0,2000)}`);
        const records = r.stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
        return { path: a.path, records: records.slice(0,limit), returned: Math.min(limit,records.length), truncated: records.length > limit, complete: records.length <= limit };
      }
      case 'pcap_analyze': {
        const p = safeWorkspace(a.path, { mustExist: true });
        const view=a.view||'summary';
        if(!['summary','conversations','fields'].includes(view)) throw new Error('Unknown PCAP view');
        if(view!=='fields') {
          const protocol=a.protocol||'ip';
          if(!['ip','ipv6','tcp','udp'].includes(protocol)) throw new Error('Invalid conversation protocol');
          const r=await runStatus('tshark',['-n','-r',p,'-q','-z',view==='summary'?'io,phs':`conv,${protocol}`],{timeout:120000,maxBuffer:8*1024*1024});
          if(r.code!==0) throw new Error(`tshark failed (${r.code}): ${r.stderr.slice(0,2000)}`);
          return {path:a.path,view,...(view==='summary'?{protocol_hierarchy:r.stdout}:{protocol,conversations:r.stdout}),complete:true};
        }
        const fields = a.fields ?? ['frame.time_epoch','ip.src','ip.dst','tcp.srcport','tcp.dstport','_ws.col.Protocol'];
        if (fields.some(f => !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(f))) throw new Error('invalid Tshark field');
        const args = ['-n', '-r', p, '-c', String(a.packet_limit ?? 1000), '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=f'];
        if (a.display_filter) args.push('-Y', a.display_filter);
        for (const f of fields) args.push('-e', f);
        const r = await runStatus('tshark', args, { timeout: 60000 });
        if (r.code !== 0) throw new Error(`tshark failed (${r.code}): ${r.stderr.slice(0,2000)}`);
        const rows = r.stdout.trimEnd().split('\n').filter(Boolean).map(line => Object.fromEntries(line.split('\t').map((v,i) => [fields[i],v])));
        const limit = a.max_rows ?? 100;
        return { fields, rows: rows.slice(0,limit), matched_in_examined_packets: rows.length, packet_limit: a.packet_limit ?? 1000, truncated: rows.length > limit, exhaustive: false };
      }
      case 'suricata_test_rules': {
        const rules = safeWorkspace(a.rules, { mustExist: true }), dir = await fs.mkdtemp(path.join(os.tmpdir(), 'suricata-rules-'));
        try {
          const validation = await runStatus('suricata', ['-T', '-S', rules, '-l', dir], { timeout: 60000 });
          if (validation.code !== 0 || !a.pcap) return { valid: validation.code === 0, validation: (validation.stdout + validation.stderr).slice(0,12000), complete: validation.code === 0 };
          const pcap = safeWorkspace(a.pcap, { mustExist: true });
          const r = await runStatus('suricata', ['-r', pcap, '-S', rules, '-l', dir, '-k', 'none', '--runmode', 'single'], { timeout: 180000 });
          const alerts = [], packets = new Set(); let totalPackets = null, count = 0;
          let eve = ''; try { eve = await fs.readFile(path.join(dir,'eve.json'),'utf8'); } catch {}
          for (const line of eve.split('\n').filter(Boolean)) {
            const event = JSON.parse(line);
            if (event.event_type === 'stats') totalPackets = event.stats?.decoder?.pkts ?? totalPackets;
            if (event.event_type === 'alert') {
              count++; if (event.pcap_cnt != null) packets.add(event.pcap_cnt);
              if (alerts.length < (a.max_alerts ?? 100)) alerts.push({ timestamp: event.timestamp, signature: event.alert?.signature, sid: event.alert?.signature_id, src_ip: event.src_ip, dest_ip: event.dest_ip, pcap_cnt: event.pcap_cnt ?? null });
            }
          }
          return { valid: true, complete: r.code === 0 && Boolean(eve), exit_code: r.code, alert_count: count, alerts, total_packets: totalPackets,
            matched_packets: packets.size, packet_hit_rate: totalPackets > 0 && (count === 0 || packets.size > 0) ? packets.size / totalPackets : null, diagnostics: r.stderr.slice(0,2000) };
        } finally { await fs.rm(dir, { recursive: true, force: true }); }
      }
      case 'osquery': {
        const query = a.query.trim().replace(/;\s*$/, '');
        if (!/^(SELECT|WITH)\s/i.test(query) || /;|--|\/\*|\b(?:ATTACH|DETACH|PRAGMA|INSERT|UPDATE|DELETE|DROP|CREATE|REPLACE|load_extension)\b/i.test(query)) throw new Error('expected one read-only SELECT/WITH query');
        const limit = a.limit ?? 100;
        const rows = parsed(await runStatus('osqueryi', ['--json', '--disable_extensions', `SELECT * FROM (${query}) LIMIT ${limit + 1};`], { timeout: 30000 }));
        if (!Array.isArray(rows)) throw new Error('osquery returned a non-array result');
        return { visibility: 'security container namespace', rows: rows.slice(0,limit), returned: Math.min(limit, rows.length), truncated: rows.length > limit, complete: rows.length <= limit };
      }
      case 'binary_analyze': {
        const p = safeWorkspace(a.path, { mustExist: true });
        if (a.address && !/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(a.address)) throw new Error('invalid disassembly address');
        const command = { info: 'ij', imports: 'iij', exports: 'iEj', strings: 'izj', functions: 'aa;aflj', disassemble: `pdj ${a.count ?? 64} @ ${a.address ?? 'entry0'}` }[a.operation ?? 'info'];
        // Open the validated file read-only, then enable r2's sandbox before
        // analysis. Enabling it before open rejects absolute workspace paths.
        return { path: a.path, operation: a.operation ?? 'info', result: parsed(await runStatus('r2', ['-N', '-q', '-e', 'scr.color=false', '-c', 'e cfg.sandbox=true;' + command, p], { timeout: 60000 })) };
      }
      default: throw new Error(`unknown extended tool: ${name}`);
    }
  }
  return { call, jobs };
}
