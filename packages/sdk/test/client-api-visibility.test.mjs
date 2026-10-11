import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import * as client from 'agenthooksprotocol/client';
const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL('../../..', import.meta.url));
const sdk = join(root, 'packages/sdk');

test('client facade exposes intentional APIs, not internal coordinators', () => {
  for (const name of ['Hooks', 'Attachment', 'AttachmentContent', 'ContentSource', 'ContentManager', 'BackendTransport', 'contract', 'form']) {
    assert.equal(typeof client[name], 'function', name);
  }
  assert.equal(typeof client.Type.Object, 'function');
  for (const name of ['UploadLimiter', 'createSharedContentManager', 'composeResponse', 'composeResponseAsync', 'normalizeEffects', 'decodeContract', 'admitContracts', 'encodeContract', 'freezeContractValue', 'projectHostInput']) {
    assert.equal(name in client, false, name);
  }
});

test('packed client declarations compile with inference and no skipLibCheck', { timeout: 60000 }, () => {
  const directory = mkdtempSync(join(tmpdir(), 'ahp-client-api-'));
  try {
    const packed = spawnSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', directory], { cwd: sdk, encoding: 'utf8', timeout: 25000 });
    assert.equal(packed.status, 0, packed.stdout + packed.stderr);
    const [{ filename }] = JSON.parse(packed.stdout);
    const modules = join(directory, 'node_modules');
    const packageDirectory = join(modules, 'agenthooksprotocol');
    mkdirSync(packageDirectory, { recursive: true });
    const extracted = spawnSync('tar', ['-xzf', join(directory, filename), '--strip-components=1', '-C', packageDirectory], { encoding: 'utf8' });
    assert.equal(extracted.status, 0, extracted.stdout + extracted.stderr);
    // Only declared dependencies are linked; the SDK itself comes from its tarball.
    const manifest = JSON.parse(readFileSync(join(packageDirectory, 'package.json'), 'utf8'));
    for (const dependency of Object.keys(manifest.dependencies)) {
      const destination = join(modules, dependency);
      mkdirSync(dirname(destination), { recursive: true });
      symlinkSync(realpathSync(join(sdk, 'node_modules', dependency)), destination, 'dir');
    }
    writeFileSync(join(directory, 'package.json'), '{"type":"module"}');
    cpSync(join(sdk, 'test/client-api-visibility-types.ts'), join(directory, 'consumer.ts'));
    const result = spawnSync(process.execPath, [require.resolve('typescript/bin/tsc'), '--noEmit', '--strict', '--exactOptionalPropertyTypes', '--noUncheckedIndexedAccess', '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', '--lib', 'ES2022,DOM', 'consumer.ts'], { cwd: directory, encoding: 'utf8', timeout: 25000 });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
