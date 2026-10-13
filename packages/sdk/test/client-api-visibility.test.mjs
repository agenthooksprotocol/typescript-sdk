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
test('typed host installation lowers directly without wire-schema revalidation', () => {
  const source = readFileSync(join(sdk, 'src/client/hooks.ts'), 'utf8');
  const initialize = source.slice(source.indexOf('  private initialize('), source.indexOf('  private async fetchAuthenticated('));
  assert.match(initialize, /hostCapabilitiesToWire\(c\)/);
  assert.doesNotMatch(initialize, /validateCapabilities\(|capabilities-response|parseJson\(|JSON\.parse\(/);
  assert.match(initialize, /validateWire\("registration", config\)/);
  assert.match(source, /options\.capabilities !== undefined && !validateCapabilities\(caps\)\.ok/);
  assert.match(source, /!isNarrower\(caps, staticCaps\)/);
});

test('metadata field checks reject malformed advertisements without interpreting opaque extensions', async () => {
  for (const manifestMetadata of [
    { authentication: true }, { transports: [false] },
    { managedPolicy: { disableable: true, scopes: 42 } },
    { limits: { maxUploadBytes: -1 } }, { limits: { maxTimeoutMs: 1.5 } },
    { limits: null }, { gaps: [{ path: 'missing-reason' }] },
  ]) {
    const hooks = new client.Hooks(aliasConfig, { source: 'urn:test:bad-metadata', harness: { name: 'test', version: '1' }, manifestMetadata,
      capabilities: { toolBefore: { intercept: { deny: true } } } });
    try {
      await assert.rejects(hooks.initialized, { name: 'ConfigurationError' });
      assert.equal(hooks.subscribes('tool.before'), false);
    } finally { await hooks.close(); }
  }
});

test('manifest metadata preserves owned advertisements and opaque extension data', async () => {
  const manifestMetadata = {
    authentication: ['bearer'], transports: ['http'], toolPaths: ['native'],
    contentCategories: ['text'], correlationIdentityFields: ['call.id'], gaps: [],
    limits: { maxUploadBytes: 1234, maxTimeoutMs: 2000, extensionLimit: 17 },
    managedPolicy: { disableable: true, scopes: ['project'] },
    extension: { attachmentLike: { type: 'text', body: { ref: 'opaque:not-uploaded', size: 999 } }, settings: { enabled: true } },
  };
  const expected = structuredClone(manifestMetadata);
  const received = [];
  const input = { session: { id: 'metadata-session' }, trigger: 'startup', permissionMode: 'default', items: [] };
  const config = { protocolVersion: 'draft', hooks: [{ id: 'metadata.backend', transport: { type: 'http', url: 'https://backend.test/hooks' }, subscriptions: [{ mode: 'intercept', events: ['session.start'], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'metadata' }, scope: 'project' }] }] };
  const hooks = new client.Hooks(config, { source: 'urn:test:metadata', harness: { name: 'test', version: '1' }, manifestMetadata,
    capabilities: { sessionStart: { intercept: { message: true } } },
    fetch: async (url, init) => {
      assert.equal(String(url), 'https://backend.test/hooks');
      const request = JSON.parse(init.body); received.push(request);
      return Response.json({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: 'draft', effects: [] } });
    } });
  try {
    manifestMetadata.authentication.push('oauth');
    manifestMetadata.managedPolicy.scopes.length = 0;
    manifestMetadata.extension.settings.enabled = false;
    await hooks.initialized;
    manifestMetadata.limits.maxUploadBytes = 9999;
    const result = await hooks.sessionStart(input);
    assert.deepEqual(result.diagnostics, []);
    assert.equal(received.length, 1);
    const { events, ...metadata } = received[0].params.event.manifest;
    assert.deepEqual(metadata, expected);
    assert.deepEqual(events, [{ event: 'session.start', modes: ['intercept'], capabilities: { effects: ['message'] } }]);
    received[0].params.event.manifest.extension.settings.enabled = false;
    const second = await hooks.sessionStart(input);
    assert.deepEqual(second.event.manifest.extension, expected.extension);
  } finally { await hooks.close(); }
});

test('untyped metadata event overrides reject before preparation or grants', async () => {
  let deliveries = 0;
  const hooks = new client.Hooks(aliasConfig, { source: 'urn:test:metadata-override', harness: { name: 'test', version: '1' }, capabilities: {},
    manifestMetadata: { events: [{ event: 'tool.before', modes: ['intercept', 'observe'], capabilities: { effects: ['deny'] } }] },
    fetch: async () => { deliveries++; throw new Error('override delivered'); } });
  try {
    await assert.rejects(hooks.initialized, { name: 'ConfigurationError' });
    assert.equal(hooks.subscribes('tool.before'), false);
    await assert.rejects(hooks.toolBefore(aliasInput), { name: 'ConfigurationError' });
    assert.equal(deliveries, 0);
  } finally { await hooks.close(); }
});

const aliasConfig = { protocolVersion: 'draft', hooks: [{ id: 'alias.backend', transport: { type: 'http', url: 'https://backend.test/hooks' }, subscriptions: ['intercept', 'observe'].map(mode => ({ mode, events: mode === 'intercept' ? ['tool.before'] : ['*'], ...(mode === 'intercept' ? { timeoutMs: 1000, failurePolicy: 'fail-open' } : {}), content: { default: 'metadata' } })) }] };
const aliasInput = { callId: 'alias', name: 'read', path: 'native', origin: 'native', input: {} };

test('typed aliases are detached before initialized waits and fixed for dispatch', async () => {
  const declarations = { toolBefore: { intercept: { deny: true } } };
  const requests = [];
  const options = { source: 'urn:test:alias', harness: { name: 'test', version: '1' }, capabilities: declarations, fetch: async (_url, init) => {
    const request = JSON.parse(init.body); requests.push(request);
    return Response.json({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: 'draft', effects: [] } });
  } };
  const hooks = new client.Hooks(aliasConfig, options);
  try {
    declarations.toolBefore.intercept.returnResult = true;
    declarations.toolBefore.observe = true;
    declarations.sessionEnd = { observe: true };
    options.capabilities = { sessionEnd: { observe: true } };
    assert.equal(hooks.subscribes('tool.before'), true);
    assert.equal(hooks.subscribes('session.end'), false);
    await hooks.initialized;
    delete declarations.toolBefore;
    await hooks.toolBefore(aliasInput);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, 'hooks/intercept');
    assert.deepEqual(requests[0].params.capabilities.effects, ['deny']);
    assert.equal(hooks.subscribes('tool.before'), true);
    assert.equal(hooks.subscribes('session.end'), false);
  } finally { await hooks.close(); }
});

test('mutated typed aliases reject atomically before preparation or backend admission', async () => {
  const cases = [
    () => { const controls = { deny: true }; controls.deny = false; return { toolBefore: { intercept: controls } }; },
    () => { const operations = ['stop']; operations.length = 0; return { toolBefore: { intercept: { flow: { operations } } } }; },
    () => { const deliverAt = ['model.before']; deliverAt.length = 0; return { toolBefore: { intercept: { inject: { context: { append: true, deliverAt } } } } }; },
    () => { const operations = ['stop']; operations.push('continue'); return { toolBefore: { intercept: { flow: { operations } } } }; },
    () => { const controls = { deny: true }; delete controls.deny; return { toolBefore: { intercept: controls } }; },
  ];
  for (const capabilities of cases.map(make => make())) {
    let preparations = 0, deliveries = 0;
    const prepare = client.ContentManager.prototype.prepare;
    client.ContentManager.prototype.prepare = function () { preparations++; throw new Error('invalid declaration prepared'); };
    const hooks = new client.Hooks(aliasConfig, { source: 'urn:test:invalid-alias', harness: { name: 'test', version: '1' }, capabilities,
      fetch: async () => { deliveries++; throw new Error('invalid declaration delivered'); } });
    try {
      await assert.rejects(hooks.initialized);
      assert.equal(hooks.subscribes('tool.before'), false);
      await assert.rejects(hooks.toolBefore(aliasInput));
      assert.equal(preparations, 0);
      assert.equal(deliveries, 0);
    } finally { client.ContentManager.prototype.prepare = prepare; await hooks.close(); }
  }
});


test('client facade exposes intentional APIs, not internal coordinators', () => {
  for (const name of ['Hooks', 'Attachment', 'AttachmentContent', 'ContentManager', 'BackendTransport', 'contract', 'form']) {
    assert.equal(typeof client[name], 'function', name);
  }
  assert.equal(typeof client.Type.Object, 'function');
  assert.equal('fromStream' in client.Attachment, false);
  assert.equal('resultBody' in client.ContentManager.prototype, false);
  assert.equal('stream' in client.Attachment.prototype, false);
  for (const name of ['CapabilityBuilder', 'capabilities', 'contentSlots', 'ContentSource', 'UploadLimiter', 'createSharedContentManager', 'composeResponse', 'composeResponseAsync', 'normalizeEffects', 'decodeContract', 'admitContracts', 'encodeContract', 'freezeContractValue', 'projectHostInput']) {
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
    source: 'urn:test:outcome', harness: { name: 'test', version: '1' }, capabilities: { toolBefore: { intercept: { deny: true } } },
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
