# Keep the complete upstream SearXNG + HTTP MCP runtime, but restore a full
# Void/musl userspace underneath it so we can add Node.js and Chromium without
# relying on a package manager in the stripped upstream runtime image.
FROM ghcr.io/whw23/searxng-http-mcp:latest AS searxng
FROM ghcr.io/void-linux/void-musl-full:latest

USER root

# Overlay the complete upstream SearXNG image onto the full Void rootfs.
# COPY merges files; it does not remove XBPS utilities that only exist in the
# full Void base. This preserves SearXNG's exact Python/runtime dependencies.
COPY --from=searxng / /

# Void's nodejs package includes npm; there is no separate `npm` XBPS package.
# Install only packages that are not already present in the SearXNG runtime.
RUN xbps-install -S \
    && for pkg in nodejs chromium tini; do \
         if ! xbps-query "$pkg" >/dev/null 2>&1; then \
           xbps-install -y "$pkg"; \
         fi; \
       done \
    && command -v node \
    && command -v npm \
    && command -v chromium \
    && command -v docker-init \
    && test -x /usr/local/searxng/custom-entrypoint.sh \
    && npm install -g --omit=dev \
         @playwright/mcp@0.0.83 \
         @modelcontextprotocol/server-memory@2026.8.31 \
         supergateway@4.0.0 \
    && npm cache clean --force \
    && rm -rf /var/cache/xbps/* /root/.npm

ENV PLAYWRIGHT_BROWSERS_PATH=0 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

COPY scripts/container-entrypoint.sh /usr/local/bin/mcp-stack-entrypoint
RUN chmod +x /usr/local/bin/mcp-stack-entrypoint \
    && mkdir -p /data/playwright /data/memory

EXPOSE 8888 8931 8932

ENTRYPOINT ["/usr/bin/docker-init", "--", "/usr/local/bin/mcp-stack-entrypoint"]
