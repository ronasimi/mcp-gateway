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

# Two Python runtimes are intentional:
#   /usr/local/bin/python  -> CPython 3.14 for searxng-http-mcp
#   /usr/bin/python3       -> Debian CPython 3.11 for the pinned SearXNG app
# SearXNG 2026.9.25 officially targets Python through 3.13, while
# searxng-http-mcp 1.2.1 requires Python 3.14+.
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
       python3 \
       python3-dev \
       python3-venv \
       tini \
       zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Pin SearXNG source, install only its runtime requirements into a dedicated
# Python 3.11 venv, and run directly from the source tree. We intentionally do
# NOT `pip install .`: SearXNG's setup.py imports the application while building
# package metadata, which makes container builds sensitive to runtime settings.
RUN set -eux; \
    git clone --filter=blob:none --no-checkout --single-branch --branch master \
      https://github.com/searxng/searxng.git /opt/searxng-src; \
    cd /opt/searxng-src; \
    git rev-parse --verify "${SEARXNG_REF}^{commit}"; \
    git checkout --detach "${SEARXNG_REF}"; \
    /usr/bin/python3 -m venv /opt/searxng-venv; \
    /opt/searxng-venv/bin/python -m pip install --no-cache-dir --upgrade pip setuptools wheel; \
    /opt/searxng-venv/bin/python -m pip install --no-cache-dir \
      -r requirements.txt -r requirements-server.txt; \
    SEARXNG_DISABLE_ETC_SETTINGS=1 PYTHONPATH=/opt/searxng-src \
      /opt/searxng-venv/bin/python -m searx.version freeze; \
    SEARXNG_DISABLE_ETC_SETTINGS=1 PYTHONPATH=/opt/searxng-src \
      /opt/searxng-venv/bin/python -c "import searx; import searx.webapp; print('SearXNG source runtime smoke test OK')"; \
    rm -rf /opt/searxng-src/.git

# The MCP wrapper is intentionally installed with CPython 3.14 because its
# published package requires Python >=3.14.
RUN set -eux; \
    /usr/local/bin/python -m pip install --no-cache-dir \
      "searxng-http-mcp==${SEARXNG_MCP_VERSION}"; \
    command -v searxng-http-mcp; \
    /usr/local/bin/python -c "import mcp; print('Python 3.14 MCP runtime OK')"

RUN npm install -g --omit=dev \
      "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" \
      "@modelcontextprotocol/server-memory@${MEMORY_MCP_VERSION}" \
      "supergateway@${SUPERGATEWAY_VERSION}" \
    && npm cache clean --force \
    && command -v node \
    && command -v npm \
    && command -v chromium \
    && command -v playwright-mcp \
    && command -v mcp-server-memory \
    && command -v supergateway

COPY scripts/container-entrypoint.sh /usr/local/bin/mcp-stack-entrypoint
RUN chmod +x /usr/local/bin/mcp-stack-entrypoint \
    && mkdir -p /etc/searxng /data/playwright /data/memory

EXPOSE 8888 8931 8932

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/mcp-stack-entrypoint"]
