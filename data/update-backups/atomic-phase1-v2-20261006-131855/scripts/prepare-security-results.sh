#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Resolve the configured runtime identity, including Compose user overrides.
identity="$(docker compose run --rm --no-deps --entrypoint node mcp-security -e 'console.log(process.getuid()+":"+process.getgid())')"
[[ "$identity" =~ ^[0-9]+:[0-9]+$ ]] || { echo 'Could not resolve Security runtime UID:GID' >&2; exit 1; }
# Extra capabilities belong only to this provisioning container, never the service.
docker compose run --rm --no-deps --user 0:0 --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --entrypoint node -e RESULTS_UID="${identity%:*}" -e RESULTS_GID=1000 mcp-security /opt/mcp/prepare-security-results.mjs --provision
docker compose run --rm --no-deps --entrypoint node mcp-security /opt/mcp/prepare-security-results.mjs
