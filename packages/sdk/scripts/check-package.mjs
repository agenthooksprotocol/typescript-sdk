import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const sdk = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const directory = mkdtempSync(join(tmpdir(), 'ahp-package-'));
const run = (command, args, cwd = directory) => execFileSync(command, args, {
  cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
});
try {
  const [packed] = JSON.parse(run('npm', ['pack', '--json', '--pack-destination', directory], sdk));
  assert(packed.files.some(file => file.path === 'dist/src/oauth/index.js'));
  assert(packed.files.some(file => file.path === 'dist/src/oauth/index.d.ts'));
  writeFileSync(join(directory, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', join(directory, packed.filename)]);
  const manifest = JSON.parse(readFileSync(join(directory, 'node_modules/agenthooksprotocol/package.json'), 'utf8'));
  assert.equal(manifest.dependencies.oauth4webapi, '3.8.8');
  assert(!JSON.stringify(manifest).includes('workspace:'));
  for (const entry of Object.values(manifest.exports)) {
    assert(readFileSync(join(directory, 'node_modules/agenthooksprotocol', entry.types)).length > 0);
    run(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(join(directory, 'node_modules/agenthooksprotocol', entry.default))})`]);
  }
  writeFileSync(join(directory, 'consumer.ts'), `import { managedOAuth } from 'agenthooksprotocol/oauth';\nimport { auth, AuthError } from 'agenthooksprotocol/client';\nvoid managedOAuth; void auth; void AuthError;\n`);
  run(process.execPath, [resolve(sdk, '../../node_modules/typescript/bin/tsc'), '--noEmit', '--strict', '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', 'consumer.ts']);
  console.log('Packed SDK exports, declarations and installed runtime dependencies verified.');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
