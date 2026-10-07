#!/usr/bin/env node
// Compatibility entrypoint. Public exports/tool names remain stable while the
// implementation is split under src/domains/network and src/adapters.
// Host-helper invariants retained by the implementation:
//   ctx.disableHostDelegation===true disables recursive socket delegation.
//   ctx.disableHostDelegation!==true requires the host helper; on failure it is
//   "refusing to substitute the mcp-security container namespace for the laptop/client LAN".
import { resolveSourceRoot } from './module-layout.mjs';
const root = resolveSourceRoot(import.meta.url);
const [tools, report, service, artifacts] = await Promise.all([
  import(new URL('domains/network/recon/tools.mjs', root)),
  import(new URL('domains/network/mdns/report.mjs', root)),
  import(new URL('domains/network/recon/service.mjs', root)),
  import(new URL('domains/network/recon/artifacts.mjs', root)),
]);
export const NETWORK_RECON_TOOLS = tools.NETWORK_RECON_TOOLS;
export const NETWORK_RECON_TOOL_NAMES = tools.NETWORK_RECON_TOOL_NAMES;
export const NETWORK_RECON_HOST_TOOL_NAMES = tools.NETWORK_RECON_HOST_TOOL_NAMES;
export const NETWORK_RECON_ACTIVE_TOOL_NAMES = tools.NETWORK_RECON_ACTIVE_TOOL_NAMES;
export const NETWORK_RECON_WORKSPACE_WRITES = tools.NETWORK_RECON_WORKSPACE_WRITES;
export const mdnsReportView = report.mdnsReportView;
export const createNetworkRecon = service.createNetworkRecon;
export const normalizeReconInput = artifacts.normalizeReconInput;
export const resultEnvelope = artifacts.resultEnvelope;
export const normalizeMapOutputBase = artifacts.normalizeMapOutputBase;
