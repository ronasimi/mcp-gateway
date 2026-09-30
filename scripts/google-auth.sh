#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

client="${GOOGLE_OAUTH_CLIENT_SOURCE:-./secrets/google-oauth-client.json}"
key="${GOOGLE_TOKEN_KEY_SOURCE:-./secrets/google-token.key}"

mkdir -p secrets data/google
chmod 700 secrets data/google 2>/dev/null || true

if [[ ! -s "$client" ]]; then
  cat >&2 <<MSG
Google OAuth client JSON not found: $client

In Google Cloud Console:
  1. Enable Gmail API, Google Calendar API, and Google Drive API.
  2. Configure the OAuth consent screen and add your account as a test user if needed.
  3. Create an OAuth 2.0 Client ID of type "Desktop app".
  4. Download its JSON to: $client

Then rerun ./scripts/google-auth.sh
MSG
  exit 2
fi

python3 - "$client" <<'PY'
import json,sys
p=sys.argv[1]
with open(p) as f: j=json.load(f)
c=j.get('installed') or j.get('web') or j
if not c.get('client_id') or not c.get('client_secret'):
    raise SystemExit(f'{p}: expected Google OAuth client JSON with client_id/client_secret')
PY

if [[ ! -s "$key" ]]; then
  openssl rand -hex 32 > "$key"
  echo "Generated Google token encryption key: $key"
fi
chmod 600 "$client" "$key" 2>/dev/null || true

echo "Building Google Workspace MCP image..."
docker compose --profile setup build mcp-google-auth

echo
echo "Starting one-time Google OAuth flow..."
echo "The container will print a Google authorization URL. Open it in a browser on this machine."
docker compose --profile setup run --rm --service-ports mcp-google-auth

echo
echo "Starting Google Workspace MCP..."
docker compose --profile google up -d mcp-google

echo "Google Workspace MCP is enabled at http://127.0.0.1:${GOOGLE_MCP_HOST_PORT:-8934}/mcp"
