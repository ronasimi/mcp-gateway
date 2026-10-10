import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

test('flat image layout initializes; missing redactor fails startup verification', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'security-image-'));
  t.after(() => fs.rm(root, {recursive:true, force:true}));
  const gateway = path.resolve(import.meta.dirname, '..');
  const dockerfile = await fs.readFile(path.join(gateway, 'Dockerfile.security'), 'utf8');
  for (const line of dockerfile.split('\n')) {
    const match = line.match(/^COPY (scripts\/.*) \/opt\/mcp\/(.*)$/);
    if (!match) continue;
    for (const source of match[1].split(' ')) await fs.copyFile(path.join(gateway, source), path.join(root, match[2] || path.basename(source)));
  }
  await fs.cp(path.join(gateway, 'src'), path.join(root, 'src'), {recursive:true});
  const verify = () => spawnSync(process.execPath, [path.join(root, 'verify-security-startup.mjs')], {encoding:'utf8', timeout:10000});
  const success = verify();
  assert.equal(success.status, 0, success.stderr);
  assert.match(success.stdout, /startup passed/);
  await fs.rm(path.join(root, 'src/core/redact.mjs'));
  const failure = verify();
  assert.notEqual(failure.status, 0);
  assert.match(failure.stderr, /redact\.mjs/);
  assert.match(dockerfile, /RUN node \/opt\/mcp\/verify-security-startup\.mjs/);
});
