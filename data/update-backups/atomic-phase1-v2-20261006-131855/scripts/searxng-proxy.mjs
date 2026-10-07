import http from 'node:http';

const listenPort = Number(process.env.SEARXNG_PROXY_PORT || 8888);
const upstreamHost = process.env.SEARXNG_UPSTREAM_HOST || 'mcp-searxng';
const upstreamPort = Number(process.env.SEARXNG_UPSTREAM_PORT || 8888);

// The upstream container is private to mcp-backend, so this proxy only needs to
// provide a stable mcp-gateway hostname/port for trusted host and ai-local clients.
const server = http.createServer((req, res) => {
  const headers = { ...req.headers };
  headers.host = `${upstreamHost}:${upstreamPort}`;

  // Remove proxy-specific hop-by-hop headers and any stale credentials a browser
  // may have cached from older authenticated revisions.
  delete headers['proxy-authorization'];
  delete headers['proxy-authenticate'];
  delete headers['x-api-key'];
  delete headers['authorization'];

  const upstream = http.request({
    hostname: upstreamHost,
    port: upstreamPort,
    method: req.method,
    path: req.url,
    headers,
  }, (upstreamRes) => {
    const responseHeaders = { ...upstreamRes.headers };
    // Do not leak stale auth challenges from a previously configured upstream.
    delete responseHeaders['www-authenticate'];
    res.writeHead(upstreamRes.statusCode || 502, responseHeaders);
    upstreamRes.pipe(res);
  });

  upstream.on('error', (error) => {
    console.error(`SearXNG proxy error: ${error.message}`);
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    }
    res.end('SearXNG upstream unavailable\n');
  });

  req.on('aborted', () => upstream.destroy());
  req.pipe(upstream);
});

server.keepAliveTimeout = 75_000;
server.headersTimeout = 80_000;
server.requestTimeout = 0;

server.listen(listenPort, '0.0.0.0', () => {
  console.error(`SearXNG proxy listening on :${listenPort} -> ${upstreamHost}:${upstreamPort}`);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
