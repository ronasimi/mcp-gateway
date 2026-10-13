# Weather/RSS and schema integration

The System server exposes `get_weather` and `get_rss_feed` through its existing endpoint on port 8933. No additional service, port, API key, or Pi extension is required. Weather returns model-derived current conditions and three forecast days including today; RSS/Atom supports bounded results and literal filtering.

The three custom servers retain all existing capabilities and now publish the supplied canonical contracts: System has 58 tools (56 existing plus weather/RSS), Security has 65, and Google Workspace has 23. Playwright, Memory, and SearXNG use their existing external servers.

## Install and rebuild

Copy the updated source into the existing `~/Projects/mcp-gateway` checkout, preserving its `.env`, secrets, and runtime data. Install local check dependencies with `npm ci` when running tests directly on the host; each custom Dockerfile installs locked dependencies during the image build.

```bash
cd ~/Projects/mcp-gateway
docker compose up -d --build mcp-system mcp-security
```

If Google Workspace is already configured, rebuild it as well:

```bash
docker compose --profile google up -d --build mcp-google
```

Restart the Pi session or reconnect the affected MCP servers to refresh cached discovery. No changes to Pi configuration are required.

## Contracts and compatibility

Canonical tool definitions live in `src/contracts/*-tools.json`; `src/contracts/migration-map.json` maps public names and arguments to the existing handlers. `src/core/tool-contracts.mjs` validates every custom call using Ajv Draft-07 with formats, references, combinators, and conditional requirements. Validation runs before execution, rejects unknown fields and invalid types, and returns bounded MCP tool errors. It does not coerce inputs or inject defaults.

Old tool names remain accepted as unlisted compatibility aliases. Calls using an old name may retain its old parameter names; callers using a canonical name must use the published parameters. For example, `network_ping_host.timeout_seconds` becomes the legacy handler's `timeout`, and `openwrt_call_ubus.arguments` is serialized to the legacy ubus handler's JSON string. Authorization, execution gates, path confinement, and stored reconnaissance artifacts remain owned by the existing handlers.

Weather/RSS reuses the supplied ESM registration module through `scripts/weather-rss-adapter.mjs`. The standalone SDK server remains runnable as `node scripts/weather-rss.mjs`; importing it never starts a second transport. Native fetch, deadlines, response limits, URL validation, and feed parsing are retained. Zod applies the feed's optional result-count default inside its handler. Tool errors are preserved by the host transport.

Three supplied Security descriptions exceeded the stack's 550-character limit because they repeated their entire scope. The repeated sentence was removed; schemas and scope metadata are preserved.

## Calls

Use the System server with its existing client discovery/call mechanism:

```json
{"name":"get_weather","arguments":{"city":"London","provinceOrState":"Ontario","country":"Canada"}}
```

```json
{"name":"get_rss_feed","arguments":{"feedUrl":"https://www.cbc.ca/webfeed/rss/rss-canada-london","maxResults":5}}
```

## Verification

```bash
npm ci
bash scripts/check.sh
```

The added tests cover all 144 name translations, timeout parameters, ubus JSON conversion, invalid inputs before dispatch, and weather/RSS through the real stack transport with mocked upstream responses. The supplied ten SDK weather/RSS tests are retained. Existing regressions test authorization and execution behavior; the flat-image fixture checks dependency resolution, startup, and passive/active metadata. Docker builds, live weather/publisher reachability, Google OAuth, and HTTP connectivity require verification on the deployment host.

Verified integration: 124 Node tests passed, two environment-dependent tests skipped (Unix socket listeners and child UID/GID switching), and all 19 Python tests passed. Catalog validation and actual Security initialization/catalog discovery passed. Docker is unavailable in the editing environment; no image build, deployed HTTP check, live weather/feed request, or account operation is claimed.
