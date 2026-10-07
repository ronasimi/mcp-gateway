import { resolveSourceRoot } from './module-layout.mjs';

const sourceRoot=resolveSourceRoot(import.meta.url);
const impl=await import(new URL('core/mcp-stdio.mjs',sourceRoot).href);

export const startMcpStdioServer=impl.startMcpStdioServer;
