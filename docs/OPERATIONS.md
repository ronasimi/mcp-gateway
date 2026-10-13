# Gateway operations

## Start and update

```bash
bash scripts/init.sh
bash scripts/status.sh
```

For an existing configured checkout, rebuild only changed owned services:

```bash
docker compose up -d --build mcp-system mcp-security
docker compose exec -T mcp-security node /opt/mcp/verify-security-startup.mjs
```

Google uses `docker compose --profile google up -d --build mcp-google`. Restart Pi and start a fresh conversation after catalog changes. Pi's prompt and tool policy are maintained in `pi-docker`; legacy stock-1.0 deploy and prompt-overwrite scripts are retired in this clean source.

## Shared workspace and state

Set `MCP_WORKSPACE_PATH` in `.env` to the absolute Pi workspace. Alternatively:

```bash
python3 scripts/configure-pi-workspace.py . ~/Projects/pi-docker
```

The helper preserves other settings and backs up `.env`; if running as root, it provisions the new workspace for UID/GID 1000. Recreate System, Security and configured Google containers after changing the mount.

| Local path | Persistent state |
| :--- | :--- |
| `data/searxng` | Search configuration |
| `data/playwright` | Browser profile |
| `data/memory` | Memory graph |
| `data/workspace` | Default workspace when no shared path is set |
| `data/ssh` | Router configuration and private keys |
| `data/google` | Encrypted account tokens |
| `data/security` | Scanner data and templates |
| `secrets` | OAuth client and token encryption key |

These directories, `.env` and update backups are excluded from clean archives and Docker build contexts. Source replacement preserves them.

## OpenWrt SSH

Store configuration and keys under `data/ssh`. The System container reads `/data/ssh/config`:

```sshconfig
Host anansi
    HostName 192.168.1.1
    User root
    IdentityFile /data/ssh/id_ed25519
    StrictHostKeyChecking accept-new

Host arachne
    HostName 192.168.1.2
    User root
    IdentityFile /data/ssh/id_ed25519
    StrictHostKeyChecking accept-new
```

Replace the example addresses with actual router addresses. Keep directories at mode 700 and private key/config files at 600, readable by the container's configured user. Verify independently:

```bash
docker compose exec -T mcp-system ssh -F /data/ssh/config anansi 'ubus call system board'
```

Use structured status for board/interface/route facts. Logs and alias names do not establish current router state.

## Google OAuth

Enable Gmail, Calendar and Drive APIs in the Google project, configure the consent screen, create a Desktop OAuth client and store its downloaded JSON at `secrets/google-oauth-client.json`. Then:

```bash
bash scripts/google-auth.sh
```

The bootstrap prints the authorization URL, receives the callback on localhost, encrypts tokens and starts the Google service. The key and token state stay server-side. Default scopes are defined in `.env.example`; account write gates default to false. Changing scopes requires reauthorization. Use `google_auth_status` to diagnose account state; do not put credentials in tool arguments.

## Gates and bounds

| Setting | Supplied default | Controls |
| :--- | :--- | :--- |
| `DOCKER_ALLOW_EXEC` | false | Container exec |
| `DOCKER_ALLOW_WRITE` | false | Docker mutations |
| `OPENWRT_ALLOW_WRITE` | false | Router mutations |
| `GOOGLE_GMAIL_WRITE`, `GOOGLE_CALENDAR_WRITE`, `GOOGLE_DRIVE_WRITE` | false | Account mutations |
| `SECURITY_ALLOW_ACTIVE` | true | Active assessment on policy-permitted targets |
| `SECURITY_ALLOW_PUBLIC_TARGETS` | false | Public target assessment |
| `SECURITY_ALLOW_PACKET_CAPTURE` | false | Packet collection |

A gate is a runtime capability setting; user authorization is still required for the requested operation. The active target allowlist and time/output bounds are documented in `.env.example`. The host helper inherits its gates at installation time; reinstall it after changing those settings.

The System container's host-root mount is read-only. Docker socket access remains a privileged host interface. Tool validation and gates bound application behavior rather than providing a network sandbox.

## Documents and images

System provides workspace-confined image inspection/transforms, document extraction/search/conversion, `pdf_read_pages`, `pdf_write_document`, `office_read_document`, `office_edit_document` and `office_export_document`. Read the discovered schema for page, cell and edit limits. Edits save output copies; overwrite controls and path confinement apply.

PDF support uses Poppler and Python PDF libraries. Office support uses LibreOffice's UNO runtime. The System image runs `verify-office-runtime.py` during its build, including text replacement through the supported document replace interface. Scanned PDFs need OCR before text extraction can recover their content.

## Troubleshooting

| Symptom | Diagnostic |
| :--- | :--- |
| Security healthy but Pi says process failed | Inspect `docker compose logs mcp-security`; run the startup verifier. Wrapper health can hide a child crash. |
| Missing `/opt/mcp/src/core/redact.mjs` | Rebuild the complete clean source; both stdio and the result reader import it. |
| SearXNG HTTP 403 | Check `data/searxng/settings.yml`: HTML/JSON formats and the local limiter overlay. |
| Host helper unavailable | Check `systemctl status mcp-security-host-recon` and its Unix socket; do not substitute Docker interfaces. |
| SSH permission denied | Check ownership/modes of `data/ssh` and the mounted config/key. |
| Google authentication failure | Check configured client/key paths and account status, then reauthorize if needed. |
| Files invisible in Pi | Align all services to the same `MCP_WORKSPACE_PATH` and recreate the affected containers. |
| Saved capture is truncated | Read the compact report artifact or selected JSON fields; do not repeat capture just to retrieve evidence. |
