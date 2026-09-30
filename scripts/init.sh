#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

ensure_env_secret() {
  local key="$1" value
  if grep -q "^${key}=" .env; then
    value="$(sed -n "s/^${key}=//p" .env | tail -n1)"
    [[ -n "$value" ]] && return 0
  fi
  value="$(openssl rand -hex 32)"
  if grep -q "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${value}|" .env
  else
    printf '\n%s=%s\n' "$key" "$value" >> .env
  fi
  echo "Generated ${key}."
}

ensure_env_secret SEARXNG_SECRET

mkdir -p data/searxng data/playwright data/memory

# Seed a known-good local/private SearXNG config on first install. Do not
# overwrite user changes on later runs.
if [[ ! -s data/searxng/settings.yml ]]; then
  cp config/searxng-settings.yml data/searxng/settings.yml
  echo "Created data/searxng/settings.yml with HTML+JSON search and limiter disabled."
fi

# Repair older generated configs that caused browser/MCP 403 responses.
python3 - <<'PY'
from pathlib import Path
p = Path('data/searxng/settings.yml')
text = p.read_text()
# Keep this migration deliberately conservative: if our required overlay keys
# are not present, append them as a final YAML override block.
required = ('formats:', '- html', '- json', 'limiter: false')
if not all(x in text for x in required):
    with p.open('a') as f:
        f.write('\n# Added by mcp-gateway local-search migration\n')
        f.write('search:\n  formats:\n    - html\n    - json\n')
        f.write('server:\n  limiter: false\n  public_instance: false\n  method: GET\n')
PY

docker compose down --remove-orphans >/dev/null 2>&1 || true

docker network inspect ai-local >/dev/null 2>&1 || {
  docker network create ai-local >/dev/null
  echo "Created external Docker network: ai-local"
}

echo "Pulling upstream SearXNG MCP image..."
docker compose pull mcp-searxng

echo "Building Playwright + Memory gateway image..."
docker compose build --pull mcp-gateway

echo "Starting MCP stack..."
docker compose up -d

echo
./scripts/status.sh
