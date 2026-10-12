import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { Readable, Writable } from 'node:stream';
import { hooks } from 'agenthooksprotocol/server';
import { serveStdio } from 'agenthooksprotocol/server/stdio';
const require = createRequire(import.meta.url);
const message = () => ({ jsonrpc: '2.0', id: 'correlated', method: 'hooks/intercept', params: {
  protocolVersion: 'draft', capabilities: { effects: ['allow', 'message'] },
  event: { id: 'correlated', source: 'urn:test:server', time: '2026-01-01T00:00:00Z', type: 'tool.before', path: 'native', call: { id: 'call' }, tool: { name: 'read', origin: 'native', input: {} } },
} });
const request = value => new Request('https://backend.test/hooks', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(value) });

test('correlated server handlers own envelopes, preserve ordered effects and opaque reply extras', async () => {
  const effects = [{ type: 'message', text: 'one' }, { type: 'allow' }, { type: 'message', text: 'two' }];
  const result = await hooks.handle(request(message()), { intercept: { toolBefore(ctx) {
    assert.equal(ctx.event.type, 'tool.before');
    ctx.event.id = 'mutated'; ctx.request.id = 'mutated'; ctx.capabilities.effects = [];
    return { effects, future: { nullable: null, ordered: [1, 2] } };
  } } });
  assert.deepEqual(await result.json(), { jsonrpc: '2.0', id: 'correlated', result: { protocolVersion: 'draft', effects, future: { nullable: null, ordered: [1, 2] } } });
});

test('empty correlated replies remain valid no-ops', async () => {
  const result = await hooks.handle(request(message()), { intercept: { toolBefore() { return {}; } } });
  assert.deepEqual(await result.json(), { jsonrpc: '2.0', id: 'correlated', result: { protocolVersion: 'draft' } });
});

test('typed server still validates dynamic grants and wrong event effects', async () => {
  const input = message(); input.params.capabilities.effects = [];
  const response = await hooks.handle(request(input), { intercept: { toolBefore() { return { effects: [{ type: 'allow' }] }; } } });
  assert.equal((await response.json()).error.code, -32004);
});

test('observation callbacks are separate from intercept callbacks and cannot return controls', async () => {
  const input = message(); delete input.id; input.method = 'hooks/observe'; delete input.params.capabilities;
  let intercepted = 0, observed = 0;
  const handlers = { intercept: { toolBefore() { intercepted++; return {}; } }, observe: { toolBefore(ctx) { observed++; assert.equal(ctx.event.type, 'tool.before'); } } };
  assert.equal((await hooks.handle(request(input), handlers)).status, 204);
  assert.deepEqual([intercepted, observed], [0, 1]);
  handlers.observe.toolBefore = () => ({ effects: [{ type: 'allow' }] });
  assert.equal((await hooks.handle(request(input), handlers)).status, 500);
});

test('HTTP and stdio share correlated handler admission and no-op envelopes', async () => {
  let output = '';
  const stdout = new Writable({ write(chunk, _encoding, done) { output += chunk; done(); } });
  await serveStdio({ intercept: { toolBefore() { return {}; } } }, { stdin: Readable.from([JSON.stringify(message()) + '\n']), stdout });
  const http = await hooks.handle(request(message()), { intercept: { toolBefore() { return {}; } } });
  assert.deepEqual(JSON.parse(output), await http.json());
});

test('external consumers compile correlated handlers and reject removed or wrong-event APIs', () => {
  const result = spawnSync(process.execPath, [require.resolve('typescript/bin/tsc'), '--noEmit', '--strict', '--exactOptionalPropertyTypes', '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', new URL('./server-correlated-types.ts', import.meta.url).pathname, new URL('../../../node-shims.d.ts', import.meta.url).pathname], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
