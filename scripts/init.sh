#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

mkdir -p data/playwright data/memory

# Recreate the project-owned backend network so upgrades from v9 cannot retain
# the old internal:true network (which blocked SearXNG Internet egress).
docker compose down --remove-orphans >/dev/null 2>&1 || true

docker network inspect ai-local >/dev/null 2>&1 || {
  docker network create ai-local >/dev/null
  echo "Created external Docker network: ai-local"
}

echo "Pulling the upstream self-contained SearXNG MCP image..."
docker compose pull mcp-searxng

echo "Building Playwright + Memory gateway image..."
docker compose build --pull mcp-gateway

echo "Starting MCP stack..."
docker compose up -d

echo
./scripts/status.sh
