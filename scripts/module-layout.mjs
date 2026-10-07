import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

// Source checkout: scripts/ is next to ../src.
// Installed runtime: compatibility entrypoints and src/ can live together.
export function resolveSourceRoot(metaUrl) {
  const sibling = new URL('../src/', metaUrl);
  if (fs.existsSync(fileURLToPath(sibling))) return sibling;
  const colocated = new URL('./src/', metaUrl);
  if (fs.existsSync(fileURLToPath(colocated))) return colocated;
  throw new Error('MCP gateway source modules are missing (expected ../src or ./src)');
}
