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

# .env is intentionally shell-compatible; load optional path/profile settings
# for the setup logic below. Docker Compose also reads the same file.
set -a
# shellcheck disable=SC1091
source .env
set +a

mkdir -p data/searxng data/playwright data/memory data/workspace data/security data/ssh data/google secrets
[[ -e data/ssh/config ]] || touch data/ssh/config
chmod 700 data/ssh data/google secrets 2>/dev/null || true
chmod 600 data/ssh/config 2>/dev/null || true

# Generate a local encryption key for Google OAuth tokens. This key is mounted
# separately from the encrypted token file and never enters model context.
google_key="${GOOGLE_TOKEN_KEY_SOURCE:-./secrets/google-token.key}"
if [[ ! -s "$google_key" ]]; then
  mkdir -p "$(dirname "$google_key")"
  openssl rand -hex 32 > "$google_key"
  chmod 600 "$google_key" 2>/dev/null || true
  echo "Generated Google token encryption key: $google_key"
fi

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

echo "Building bounded system-tools MCP image..."
docker compose build --pull mcp-system

echo "Building security CLI suite..."
docker compose build --pull mcp-security

echo "Starting MCP stack..."
docker compose up -d

# Google is optional because Compose must not require an OAuth client secret on
# installations that do not use account tools. If the client JSON exists, start
# the bounded Google MCP; authorization can be completed with google-auth.sh.
google_client="${GOOGLE_OAUTH_CLIENT_SOURCE:-./secrets/google-oauth-client.json}"
if [[ -s "$google_client" ]]; then
  echo "Building Google Workspace MCP image..."
  docker compose --profile google build --pull mcp-google
  echo "Starting Google Workspace MCP..."
  docker compose --profile google up -d mcp-google
else
  echo "Google Workspace MCP disabled (no OAuth client at $google_client)."
  echo "To enable it, place a Desktop OAuth client JSON there and run ./scripts/google-auth.sh"
fi

echo
./scripts/status.sh
