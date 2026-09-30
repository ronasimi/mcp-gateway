import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

export const CLIENT_FILE = process.env.GOOGLE_OAUTH_CLIENT_FILE || '/run/secrets/google_oauth_client';
export const TOKEN_KEY_FILE = process.env.GOOGLE_TOKEN_KEY_FILE || '/run/secrets/google_token_key';
export const TOKEN_FILE = process.env.GOOGLE_TOKEN_FILE || '/data/google/token.enc.json';
export const WORKSPACE = path.resolve(process.env.MCP_WORKSPACE || '/workspace');

function parseKey(raw) {
  const text = raw.trim();
  let key;
  if (/^[0-9a-fA-F]{64}$/.test(text)) key = Buffer.from(text, 'hex');
  else {
    try { key = Buffer.from(text, 'base64'); } catch { key = Buffer.from(text); }
  }
  if (key.length !== 32) throw new Error('GOOGLE token encryption key must decode to exactly 32 bytes');
  return key;
}

export async function loadClient() {
  const raw = await fsp.readFile(CLIENT_FILE, 'utf8');
  const json = JSON.parse(raw);
  const cfg = json.installed || json.web || json;
  if (!cfg.client_id || !cfg.client_secret) throw new Error(`Google OAuth client file ${CLIENT_FILE} is missing client_id/client_secret`);
  return {
    client_id: cfg.client_id,
    client_secret: cfg.client_secret,
    auth_uri: cfg.auth_uri || 'https://accounts.google.com/o/oauth2/v2/auth',
    token_uri: cfg.token_uri || 'https://oauth2.googleapis.com/token',
    redirect_uris: cfg.redirect_uris || [],
  };
}

async function loadKey() {
  return parseKey(await fsp.readFile(TOKEN_KEY_FILE, 'utf8'));
}

export async function encryptJson(value) {
  const key = await loadKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(value));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    version: 1,
    algorithm: 'AES-256-GCM',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

export async function decryptJson(envelope) {
  if (!envelope || envelope.version !== 1 || envelope.algorithm !== 'AES-256-GCM') throw new Error('Unsupported Google token file format');
  const key = await loadKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString('utf8'));
}

export async function loadToken() {
  const envelope = JSON.parse(await fsp.readFile(TOKEN_FILE, 'utf8'));
  return decryptJson(envelope);
}

export async function saveToken(token) {
  await fsp.mkdir(path.dirname(TOKEN_FILE), { recursive: true, mode: 0o700 });
  const envelope = await encryptJson(token);
  const tmp = `${TOKEN_FILE}.tmp-${process.pid}`;
  await fsp.writeFile(tmp, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 });
  await fsp.rename(tmp, TOKEN_FILE);
  await fsp.chmod(TOKEN_FILE, 0o600).catch(() => {});
}

export function tokenExists() {
  return fs.existsSync(TOKEN_FILE);
}

export function parseScopes(value = process.env.GOOGLE_SCOPES || '') {
  const fallback = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/calendar.calendarlist.readonly',
    'https://www.googleapis.com/auth/calendar.events.readonly',
    'https://www.googleapis.com/auth/calendar.freebusy',
    'https://www.googleapis.com/auth/drive.readonly',
  ];
  const scopes = value.trim() ? value.split(/[\s,]+/).filter(Boolean) : fallback;
  return [...new Set(scopes)];
}

export async function exchangeAuthorizationCode({ code, redirectUri }) {
  const client = await loadClient();
  const body = new URLSearchParams({
    code,
    client_id: client.client_id,
    client_secret: client.client_secret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });
  const res = await fetch(client.token_uri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const payload = await res.json().catch(async () => ({ raw: await res.text() }));
  if (!res.ok) throw new Error(`Google OAuth code exchange failed (${res.status}): ${JSON.stringify(payload)}`);
  const now = Date.now();
  const token = {
    ...payload,
    obtained_at: new Date(now).toISOString(),
    expiry_date: payload.expires_in ? now + Number(payload.expires_in) * 1000 : undefined,
  };
  await saveToken(token);
  return token;
}

export async function getAccessToken() {
  let token;
  try { token = await loadToken(); }
  catch (e) {
    if (e?.code === 'ENOENT') throw new Error('Google account is not authorized. Run ./scripts/google-auth.sh first.');
    throw e;
  }
  if (token.access_token && Number(token.expiry_date || 0) > Date.now() + 90_000) return token.access_token;
  if (!token.refresh_token) throw new Error('Google token has no refresh_token. Re-run ./scripts/google-auth.sh with offline access.');

  const client = await loadClient();
  const body = new URLSearchParams({
    client_id: client.client_id,
    client_secret: client.client_secret,
    refresh_token: token.refresh_token,
    grant_type: 'refresh_token',
  });
  const res = await fetch(client.token_uri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const payload = await res.json().catch(async () => ({ raw: await res.text() }));
  if (!res.ok) throw new Error(`Google token refresh failed (${res.status}): ${JSON.stringify(payload)}`);
  token = {
    ...token,
    ...payload,
    refresh_token: payload.refresh_token || token.refresh_token,
    obtained_at: new Date().toISOString(),
    expiry_date: payload.expires_in ? Date.now() + Number(payload.expires_in) * 1000 : token.expiry_date,
  };
  await saveToken(token);
  return token.access_token;
}

export async function googleFetch(url, options = {}) {
  const accessToken = await getAccessToken();
  const headers = new Headers(options.headers || {});
  headers.set('authorization', `Bearer ${accessToken}`);
  const res = await fetch(url, { ...options, headers });
  const contentType = res.headers.get('content-type') || '';
  let body;
  if (contentType.includes('application/json')) body = await res.json();
  else body = Buffer.from(await res.arrayBuffer());
  if (!res.ok) {
    const detail = Buffer.isBuffer(body) ? body.toString('utf8').slice(0, 4000) : JSON.stringify(body).slice(0, 4000);
    throw new Error(`Google API ${res.status} ${res.statusText}: ${detail}`);
  }
  return { body, headers: res.headers, status: res.status };
}

export function safeWorkspace(rel, { mustExist = false } = {}) {
  if (typeof rel !== 'string' || !rel.trim()) throw new Error('workspace path must be a non-empty string');
  const resolved = path.resolve(WORKSPACE, rel);
  const prefix = WORKSPACE.endsWith(path.sep) ? WORKSPACE : `${WORKSPACE}${path.sep}`;
  if (resolved !== WORKSPACE && !resolved.startsWith(prefix)) throw new Error('workspace path escapes MCP_WORKSPACE');
  if (mustExist && !fs.existsSync(resolved)) throw new Error(`workspace path not found: ${rel}`);
  return resolved;
}

export function clipText(value, max = 65536) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  if (text.length <= max) return text;
  return `${text.slice(0, max)}\n…[truncated ${text.length - max} characters]`;
}

export function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

export function base64UrlDecode(value = '') {
  return Buffer.from(value, 'base64url').toString('utf8');
}

export function quoteDriveLiteral(value) {
  return String(value).replaceAll('\\', '\\\\').replaceAll("'", "\\'");
}
