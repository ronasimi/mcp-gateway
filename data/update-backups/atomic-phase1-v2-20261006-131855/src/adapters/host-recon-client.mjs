import fs from 'node:fs';
import http from 'node:http';

export function createHostReconClient({ socketPath = '', disabled = false } = {}) {
  const socket = disabled ? '' : String(socketPath || '').trim();

  function available() {
    return Boolean(socket && fs.existsSync(socket));
  }

  async function call(tool, args = {}) {
    if (!socket) return null;
    const body = JSON.stringify({ tool, args });
    if (Buffer.byteLength(body) > 4 * 1024 * 1024) throw new Error('host recon request exceeds 4 MiB');

    return await new Promise((resolve, reject) => {
      const req = http.request({
        socketPath: socket,
        path: '/call',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      }, res => {
        let raw = '';
        let bytes = 0;
        res.on('data', chunk => {
          bytes += chunk.length;
          if (bytes <= 8 * 1024 * 1024) raw += chunk.toString('utf8');
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(raw || '{}');
            if (res.statusCode !== 200 || parsed.error) reject(new Error(parsed.error || `host recon helper HTTP ${res.statusCode}`));
            else resolve(parsed.result);
          } catch (error) {
            reject(new Error(`invalid host recon helper response: ${error.message}`));
          }
        });
      });
      req.setTimeout(650000, () => req.destroy(new Error('host recon helper timeout')));
      req.on('error', reject);
      req.end(body);
    });
  }

  return { available, call, socketPath: socket };
}
