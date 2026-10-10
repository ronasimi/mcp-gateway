# Gateway development

## One check command

```bash
bash scripts/check.sh
```

Use Node 22, Python 3 and `jq`. Python PDF tests need ReportLab and either pypdf or PyPDF2; packet fixtures need Scapy. Packet-worker tests use fixtures; live captures and scans are not part of the source check. The System image verifies real LibreOffice/UNO integration separately during its build.

The command runs all `*.test.mjs` suites, current `*-test.py` suites, the curated catalog validator and actual Security initialization/catalog discovery. Environment-dependent tests explicitly skip only unsupported Unix socket binding or UID/GID switching. These skips are limitations, not successful live validation.

## Source boundaries

| Directory | Responsibility |
| :--- | :--- |
| `src/core` | Transport, schemas and redaction |
| `src/adapters` | External-runtime and host-helper interfaces |
| `src/domains` | Capability implementations, parsers and reporting |
| `scripts` | Server entrypoints, compatibility loaders and operational scripts |
| `tests` | Unit, policy, worker and protocol contracts |

Dependencies point from entrypoints to domains/adapters to core. Core does not import a domain, and domains do not import server entrypoints. Runtime images copy both compatibility loaders and the complete shared `src` tree.

## Tests retained

| Suites | Focus |
| :--- | :--- |
| Architecture and deduplication | Module direction, image dependencies, catalogs and schema overlap |
| Security and isolation | Target validation, gates, deadlines, process bounds and namespace provenance |
| mDNS and network evidence | Wire parsing, normalization, range arithmetic, completeness and uncertain findings |
| Passive capture/map and recon contracts | Saved evidence, recovery paths, output rendering and partial phases |
| Redaction and result reader | Sanitization before encoding, confined selectors and bounded retrieval |
| Security startup | Actual initialize/catalog in the flat image layout; missing-redactor failure |
| OpenWrt status | Structured board/interface/route observations |
| Document and Python workers | Schema bounds, copy semantics, confinement and document parsing |
| Workspace and permissions | Shared settings and narrow result-directory provisioning |

Revision-specific names were normalized. Legacy Pi-1.0 prompt/install tests and scripts were removed together; the current Pi repo owns its own prompt and fixed-tool policy tests. No supported gateway capability test was removed.

## Discovery catalog

Owned tools publish `_meta["ai.catalog"]` with domain, aliases, scope, overlap group and preferred use. Searchable descriptions distinguish host versus container state, metadata versus content, count versus list and passive versus active operations. Strict input schemas and server-side validation remain the execution boundary.

`node scripts/validate-catalog.mjs` checks the live stdio catalogs against curated metadata. [The catalog](TOOL-CATALOG.md) is generated from current `tools/list` responses, not historical counts.

## Validation limits

Offline tests establish parser, policy and protocol behavior. Docker build gates verify installed Office/runtime dependencies. Real LAN delivery, router access, account authorization, browser availability and Pi-to-MCP HTTP connectivity require checks on the deployment host.

## Masscan regressions

`tests/masscan.test.mjs` checks normalized CIDRs, required port expressions, scope/rate feasibility, total probe caps, argv construction, parser deduplication and scope filtering, timeout/output-limit status, active/allowlist/config gates, and durable spilled evidence. An actual stdio MCP dispatch test substitutes a stub binary and verifies that denied calls never start it. Docker startup fixtures validate active/non-idempotent metadata. The image runs native `--regress` and `--echo` checks without sending scan packets; executing those checks requires a Docker build.
