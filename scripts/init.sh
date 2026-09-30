#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

if ! grep -q '^MCP_GATEWAY_AUTH_TOKEN=.' .env; then
  token="$(openssl rand -hex 32)"
  if grep -q '^MCP_GATEWAY_AUTH_TOKEN=' .env; then
    sed -i "s|^MCP_GATEWAY_AUTH_TOKEN=.*|MCP_GATEWAY_AUTH_TOKEN=${token}|" .env
  else
    printf '\nMCP_GATEWAY_AUTH_TOKEN=%s\n' "$token" >> .env
  fi
  echo "Created .env with a random local stack secret."
fi

mkdir -p data/searxng data/playwright data/memory

docker network inspect ai-local >/dev/null 2>&1 || {
  docker network create ai-local >/dev/null
  echo "Created external Docker network: ai-local"
}

echo "Building SearXNG + Playwright + Memory MCP image..."
docker compose build --pull

echo "Starting MCP stack..."
docker compose up -d

echo
./scripts/status.sh
