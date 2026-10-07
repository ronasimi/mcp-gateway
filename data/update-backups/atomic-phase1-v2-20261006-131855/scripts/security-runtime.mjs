import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';

// Use argv throughout; close stdin for one-shot commands and kill the entire
// process group at the deadline (msfconsole can spawn descendants).
export function runStatus(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args.map(String), {
      cwd: options.cwd, env: { ...process.env, ...options.env },
      detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '', bytes = 0, timedOut = false, outputLimited = false;
    const cap = options.maxBuffer ?? 8 * 1024 * 1024;
    const kill = () => killGroup(child);
    const timer = setTimeout(() => { timedOut = true; kill(); }, options.timeout ?? 60000);
    for (const [stream, isError] of [[child.stdout, false], [child.stderr, true]]) {
      stream.on('data', chunk => {
        const remaining = Math.max(0, cap - bytes);
        bytes += chunk.length;
        const text = chunk.subarray(0, remaining).toString('utf8');
        if (isError) stderr += text; else stdout += text;
        if (bytes > cap) { outputLimited = true; kill(); }
      });
    }
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code: timedOut ? 124 : outputLimited ? 125 : (code ?? 128),
        stdout, stderr, timed_out: timedOut, output_limited: outputLimited, signal });
    });
  });
}

export function killGroup(child) {
  if (!child.pid) return;
  try { process.kill(-child.pid, 'SIGKILL'); }
  catch (error) { if (error.code !== 'ESRCH') child.kill('SIGKILL'); }
}

export function confinedPath(root, relative = '.', { mustExist = false } = {}) {
  if (typeof relative !== 'string' || relative.includes('\0')) throw new Error('invalid workspace path');
  const base = path.resolve(root), resolved = path.resolve(base, relative);
  const inside = candidate => candidate === base || candidate.startsWith(base + path.sep);
  if (!inside(resolved)) throw new Error('path escapes workspace');
  // Check existing ancestors too, so a new file under an escaping symlink fails.
  let ancestor = resolved;
  while (!fs.existsSync(ancestor)) {
    if (fs.lstatSync(ancestor, { throwIfNoEntry: false })?.isSymbolicLink()) throw new Error('dangling symlink');
    if (ancestor === base) break;
    ancestor = path.dirname(ancestor);
  }
  if (fs.existsSync(ancestor)) {
    const realBase = fs.realpathSync(base), real = fs.realpathSync(ancestor);
    if (real !== realBase && !real.startsWith(realBase + path.sep)) throw new Error('symlink escapes workspace');
  }
  if (mustExist && !fs.existsSync(resolved)) throw new Error(`workspace path not found: ${relative}`);
  return resolved;
}

export function validateArguments(schema, value, name = 'arguments') {
  if (Array.isArray(schema.type)) {
    for (const type of schema.type) { try { validateArguments({...schema,type},value,name); return; } catch {} }
    throw new Error(`${name} must match one of ${schema.type.join(', ')}`);
  }
  if (schema.type === 'null') { if(value !== null) throw new Error(`${name} must be null`); return; }
  if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${name} must be an object`);
    for (const key of schema.required ?? []) if (!(key in value)) throw new Error(`${name}.${key} is required`);
    for (const [key, item] of Object.entries(value)) {
      if (schema.properties?.[key]) validateArguments(schema.properties[key], item, `${name}.${key}`);
      else if (schema.additionalProperties === false) throw new Error(`unknown ${name}.${key}`);
      else if (typeof schema.additionalProperties === 'object') validateArguments(schema.additionalProperties, item, `${name}.${key}`);
    }
  } else if (schema.type === 'array') {
    if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
    if (schema.maxItems != null && value.length > schema.maxItems) throw new Error(`${name} has too many items`);
    if (schema.minItems != null && value.length < schema.minItems) throw new Error(`${name} has too few items`);
    value.forEach((v, i) => validateArguments(schema.items, v, `${name}[${i}]`));
  } else {
    const type = schema.type === 'integer' ? 'number' : schema.type;
    if (type && typeof value !== type) throw new Error(`${name} must be ${schema.type}`);
    if (type === 'number' && (!Number.isFinite(value) || (schema.type === 'integer' && !Number.isInteger(value)) || value < (schema.minimum ?? -Infinity) || value > (schema.maximum ?? Infinity))) throw new Error(`${name} is out of range`);
    if (type === 'string' && (value.includes('\0') || value.length < (schema.minLength ?? 0) || value.length > (schema.maxLength ?? 8192))) throw new Error(`${name} has invalid length/content`);
  }
  if (schema.enum && !schema.enum.includes(value)) throw new Error(`${name} must be one of ${schema.enum.join(', ')}`);
}

export class JobManager {
  constructor({ maxJobs = 2, maxBytes = 256 * 1024 } = {}) { this.jobs = new Map(); this.maxJobs = maxJobs; this.maxBytes = maxBytes; }
  async start(command, args, { timeout = 120000, label = command, cwd, env, cleanup, interactive = false } = {}) {
    if ([...this.jobs.values()].filter(j => j.status === 'running').length >= this.maxJobs) throw new Error('security job limit reached; poll or stop a running job');
    while (this.jobs.size >= 20) {
      const done = [...this.jobs.values()].find(j => j.status !== 'running');
      if (!done) break;
      this.jobs.delete(done.id);
    }
    const child = spawn(command, args.map(String), { cwd, env: { ...process.env, ...env }, detached: true, stdio: [interactive ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    const job = { id: randomUUID(), label, child, interactive, status: 'running', output: Buffer.alloc(0), total: 0, dropped: 0, started: new Date().toISOString() };
    this.jobs.set(job.id, job);
    child.stdin?.on('error', () => {});
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
      job.total += chunk.length;
      job.output = Buffer.concat([job.output, chunk]);
      if (job.output.length > this.maxBytes) {
        const removed = job.output.length - this.maxBytes;
        job.dropped += removed;
        job.output = job.output.subarray(removed);
      }
    });
    const timer = setTimeout(() => { job.status = 'timed_out'; killGroup(child); }, timeout);
    child.on('close', async (code, signal) => {
      clearTimeout(timer);
      job.exit_code = code; job.signal = signal; job.finished = new Date().toISOString();
      if (job.status === 'running') job.status = code === 0 ? 'completed' : 'failed';
      if (cleanup) await cleanup().catch(() => {});
    });
    await new Promise((resolve, reject) => {
      child.once('spawn', resolve);
      child.once('error', error => { clearTimeout(timer); job.status = 'failed'; job.error = error.message; reject(error); });
    });
    return this.status(job.id);
  }
  get(id) { const job = this.jobs.get(id); if (!job) throw new Error('unknown job; jobs expire on container restart'); return job; }
  status(id, offset = 0, maxBytes = 8192) {
    const j = this.get(id), start = Math.max(j.dropped, offset);
    const chunk = j.output.subarray(start - j.dropped, start - j.dropped + maxBytes);
    return { job_id: id, label: j.label, status: j.status, exit_code: j.exit_code ?? null, signal: j.signal ?? null, started: j.started,
      output: chunk.toString('utf8'), offset: start, next_offset: start + chunk.length,
      has_more: start + chunk.length < j.total, dropped_bytes: j.dropped,
      elapsed_ms: Date.now() - Date.parse(j.started),
      complete: j.status === 'completed', error: j.error ?? null };
  }
  send(id, input) {
    const j = this.get(id);
    if (j.status !== 'running' || !j.interactive || !j.child.stdin?.writable) throw new Error('job has no writable input');
    j.child.stdin.write(input);
    return { job_id: id, bytes_sent: Buffer.byteLength(input) };
  }
  stop(id) { const j = this.get(id); if (j.status === 'running') { j.status = 'stopped'; killGroup(j.child); } return this.status(id); }
  stopAll() { for (const job of this.jobs.values()) this.stop(job.id); }
}
