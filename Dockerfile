FROM ghcr.io/whw23/searxng-http-mcp:latest

# Keep the image self-contained: SearXNG MCP + Playwright MCP + system Chromium.
# The upstream SearXNG image is Alpine-based.
RUN apk add --no-cache \
      nodejs \
      npm \
      chromium \
      tini \
    && npm install -g --omit=dev @playwright/mcp@0.0.83 \
    && npm cache clean --force

COPY scripts/container-entrypoint.sh /usr/local/bin/mcp-stack-entrypoint
RUN chmod +x /usr/local/bin/mcp-stack-entrypoint

EXPOSE 8888 8931

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/mcp-stack-entrypoint"]
