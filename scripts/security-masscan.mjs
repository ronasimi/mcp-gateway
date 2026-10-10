import {resolveSourceRoot} from './module-layout.mjs';
const module = await import(new URL('domains/network/masscan.mjs',resolveSourceRoot(import.meta.url)));
export const {MASSCAN_TOOL,createMasscan,masscanTarget,masscanPorts,parseMasscanList} = module;
