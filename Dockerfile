FROM python:3.14-slim-bookworm

ARG SEARXNG_REF=12f8b6515
ARG SEARXNG_MCP_VERSION=1.2.1
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
ARG MEMORY_MCP_VERSION=2026.8.31
ARG SUPERGATEWAY_VERSION=4.0.0

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=0 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    SEARXNG_URL=http://127.0.0.1:8080

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       ca-certificates \
       chromium \
       curl \
       git \
       libffi-dev \
       libssl-dev \
       libxml2-dev \
       libxslt1-dev \
       nodejs \
       npm \
       tini \
       zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install SearXNG from an explicit upstream revision on the same glibc/Python
# runtime used at execution time. This avoids cross-distro rootfs overlays.
RUN git clone --filter=blob:none --no-checkout --single-branch --branch master \
         https://github.com/searxng/searxng.git /opt/searxng-src \
    && cd /opt/searxng-src \
    && git rev-parse --verify "${SEARXNG_REF}^{commit}" \
    && git checkout --detach "${SEARXNG_REF}" \
    && python -m pip install --no-cache-dir --upgrade pip setuptools wheel pyyaml msgspec typing-extensions pybind11 \
    && SEARXNG_DISABLE_ETC_SETTINGS=1 python -m pip install --no-cache-dir --use-pep517 --no-build-isolation . \
    && python -m pip install --no-cache-dir \
         granian==2.7.9 \
         "searxng-http-mcp==${SEARXNG_MCP_VERSION}" \
    && SEARXNG_DISABLE_ETC_SETTINGS=1 python -c "import searx; import searx.webapp; print('SearXNG import smoke test OK')" \
    && rm -rf /opt/searxng-src/.git

RUN npm install -g --omit=dev \
      "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" \
      "@modelcontextprotocol/server-memory@${MEMORY_MCP_VERSION}" \
      "supergateway@${SUPERGATEWAY_VERSION}" \
    && npm cache clean --force \
    && command -v node \
    && command -v npm \
    && command -v chromium \
    && command -v granian \
    && command -v searxng-http-mcp \
    && command -v playwright-mcp \
    && command -v mcp-server-memory \
    && command -v supergateway

COPY scripts/container-entrypoint.sh /usr/local/bin/mcp-stack-entrypoint
RUN chmod +x /usr/local/bin/mcp-stack-entrypoint \
    && mkdir -p /etc/searxng /data/playwright /data/memory

EXPOSE 8888 8931 8932

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/mcp-stack-entrypoint"]
