# SearXNG HTTP MCP is built on SearXNG's stripped Void Linux/musl runtime.
# That runtime intentionally removes XBPS, so it cannot be extended with apk/apt.
# Rehydrate the same application onto a full Void/musl base, where XBPS can
# install Node.js + Chromium for Playwright MCP.
FROM ghcr.io/whw23/searxng-http-mcp:latest AS searxng

FROM ghcr.io/void-linux/void-musl-full:latest

USER root

RUN xbps-install -Suy xbps \
    && xbps-install -Sy \
         ca-certificates \
         chromium \
         libstdc++ \
         nodejs \
         npm \
         python3 \
         tini \
         tzdata \
         wget \
    && npm install -g --omit=dev @playwright/mcp@0.0.83 \
    && npm cache clean --force \
    && rm -rf /var/cache/xbps/*

# Copy the self-contained SearXNG + HTTP MCP application and its runtime data
# from the upstream image. Runtime packages above provide the OS libraries that
# its venv and entrypoints expect.
COPY --from=searxng /usr/local/searxng /usr/local/searxng
COPY --from=searxng /etc/searxng /etc/searxng
COPY --from=searxng /var/cache/searxng /var/cache/searxng

ENV PATH="/usr/local/searxng/.venv/bin:/usr/local/bin:/usr/bin:/bin" \
    __SEARXNG_CONFIG_PATH="/etc/searxng" \
    __SEARXNG_DATA_PATH="/var/cache/searxng" \
    PLAYWRIGHT_BROWSERS_PATH=0 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

COPY scripts/container-entrypoint.sh /usr/local/bin/mcp-stack-entrypoint
RUN chmod +x /usr/local/bin/mcp-stack-entrypoint \
    && mkdir -p /data/playwright /etc/searxng /var/cache/searxng

EXPOSE 8888 8931

ENTRYPOINT ["/usr/bin/docker-init", "--", "/usr/local/bin/mcp-stack-entrypoint"]
