// Compatibility entrypoint. Implementation lives in src/domains/network/mdns.
import { resolveSourceRoot } from './module-layout.mjs';
const root = resolveSourceRoot(import.meta.url);
const mdns = await import(new URL('domains/network/mdns/index.mjs', root));
export const addressRange = mdns.addressRange;
export const normalizeMdnsRecords = mdns.normalizeMdnsRecords;
export const inferMdnsSubnets = mdns.inferMdnsSubnets;
export const parseMdnsPacket = mdns.parseMdnsPacket;
export const collectMdns = mdns.collectMdns;
