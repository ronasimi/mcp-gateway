#!/usr/bin/env node
import http from 'node:http';
import crypto from 'node:crypto';
import { loadClient, parseScopes, exchangeAuthorizationCode, TOKEN_FILE } from './google-common.mjs';

const port = Number(process.env.GOOGLE_OAUTH_CALLBACK_PORT || 53682);
const redirectUri = `http://127.0.0.1:${port}/oauth2callback`;
const scopes = parseScopes();
const state = crypto.randomBytes(24).toString('base64url');
const client = await loadClient();

const auth = new URL(client.auth_uri);
auth.searchParams.set('client_id', client.client_id);
auth.searchParams.set('redirect_uri', redirectUri);
auth.searchParams.set('response_type', 'code');
auth.searchParams.set('scope', scopes.join(' '));
auth.searchParams.set('access_type', 'offline');
auth.searchParams.set('include_granted_scopes', 'true');
auth.searchParams.set('prompt', process.env.GOOGLE_OAUTH_PROMPT || 'consent');
auth.searchParams.set('state', state);

console.log('\nGoogle Workspace authorization');
console.log('================================');
console.log('Open this URL in a browser on this machine:\n');
console.log(auth.toString());
console.log(`\nWaiting for OAuth callback on ${redirectUri}`);
console.log(`Requested scopes:\n- ${scopes.join('\n- ')}\n`);

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url || '/', redirectUri);
    if (u.pathname !== '/oauth2callback') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      return res.end('Not found');
    }
    if (u.searchParams.get('state') !== state) throw new Error('OAuth state mismatch');
    const oauthError = u.searchParams.get('error');
    if (oauthError) throw new Error(`Google authorization failed: ${oauthError}`);
    const code = u.searchParams.get('code');
    if (!code) throw new Error('OAuth callback did not include an authorization code');
    const token = await exchangeAuthorizationCode({ code, redirectUri });
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><title>Google authorization complete</title><h1>Google authorization complete</h1><p>You may close this tab.</p>');
    console.log(`Authorization complete. Encrypted token saved to ${TOKEN_FILE}.`);
    console.log(`Granted scopes: ${token.scope || scopes.join(' ')}`);
    server.close(() => process.exit(0));
  } catch (e) {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`Authorization failed: ${e?.message || e}`);
    console.error(e?.stack || String(e));
    server.close(() => process.exit(1));
  }
});

server.listen(port, '0.0.0.0');
