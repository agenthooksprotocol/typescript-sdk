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
  for (const name of ['Hooks', 'Attachment', 'AttachmentContent', 'ContentManager', 'BackendTransport', 'contract', 'form']) {
    assert.equal(typeof client[name], 'function', name);
  }
  assert.equal(typeof client.Type.Object, 'function');
  assert.equal('fromStream' in client.Attachment, false);
  assert.equal('resultBody' in client.ContentManager.prototype, false);
  assert.equal('stream' in client.Attachment.prototype, false);
  for (const name of ['contentSlots', 'ContentSource', 'UploadLimiter', 'createSharedContentManager', 'composeResponse', 'composeResponseAsync', 'normalizeEffects', 'decodeContract', 'admitContracts', 'encodeContract', 'freezeContractValue', 'projectHostInput']) {
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

test('consumer outcome exposes a single typed representation for each settled fact', async () => {
  const hooks = new client.Hooks({ protocolVersion: 'draft', hooks: [{ id: 'outcome.backend', transport: { type: 'http', url: 'https://backend.test/hooks' }, subscriptions: [{ mode: 'intercept', events: ['tool.before'], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'metadata' } }] }] }, {
    source: 'urn:test:outcome', capabilities: { 'tool.before': { effects: [] } },
    fetch: async (_url, init) => Response.json({ jsonrpc: '2.0', id: JSON.parse(init.body).id, result: { protocolVersion: 'draft', effects: [] } }),
  });
  try {
    const result = await hooks.toolBefore({ callId: 'call', name: 'read', path: 'native', origin: 'native', input: { count: 1 } });
    assert.deepEqual(result.event.tool.input, { count: 1 });
    assert.equal(result.state.permission, 'none');
    assert.deepEqual(result.effects, []);
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.acceptedResponses.length, 1);
    for (const field of ['input', 'permission', 'response', 'errors', 'settledEvent', 'effectiveEvent', 'observations'])
      assert.equal(Object.hasOwn(result, field), false, field);
  } finally { await hooks.close(); }
});
