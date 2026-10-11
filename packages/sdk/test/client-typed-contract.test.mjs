import test from 'node:test';
import assert from 'node:assert/strict';
import { Hooks } from 'agenthooksprotocol/client';
import { validateInterceptResponse } from 'agenthooksprotocol/draft';
import { hooks as backendHooks } from 'agenthooksprotocol/server';

const text = (id, value) => ({ id, kind: 'text', mediaType: 'text/plain', selection: 'body', text: value });
const message = (id, role = 'user') => ({ id, role, parts: [text(`${id}.text`, id)] });
const edit = (target, value) => ({ type: 'modify', target, operation: 'replace', value });
function client(type, capabilities, reply, count = 1) {
  return new Hooks({ protocolVersion: 'draft', hooks: Array.from({ length: count }, (_, index) => ({
    id: `test.typed.backend${index}`, transport: { type: 'http', url: `https://backend${index}.test/hooks` },
    subscriptions: [{ mode: 'intercept', events: [type], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'body' } }],
  })) }, { source: 'urn:test:typed', capabilities: { [type]: capabilities }, fetch: async (url, init) => {
    const wire = JSON.parse(init.body);
    return Response.json({ jsonrpc: '2.0', id: wire.id, result: { protocolVersion: 'draft', ...reply(wire, String(url)) } });
  } });
}
const caps = target => ({ effects: ['modify'], modify: { [target]: { replace: true, merge: false } } });

for (const result of [{ protocolVersion: 'draft' }, { protocolVersion: 'draft', effects: [] }]) {
  test(`neutral response ${Object.hasOwn(result, 'effects') ? 'empty' : 'absent'} settles to typed empty effects without mutating wire`, async () => {
    const wire = { jsonrpc: '2.0', id: 'event', result };
    const before = structuredClone(wire);
    Object.freeze(result);
    Object.freeze(wire);
    const parsed = validateInterceptResponse(wire);
    assert.equal(parsed.ok, true);
    assert.deepEqual(parsed.value.result.effects ?? [], []);
    assert.deepEqual(wire, before);
    const hooks = client('tool.before', { effects: [] }, () => result);
    const settled = await hooks.toolBefore({ callId: 'call', name: 'read', input: {}, path: 'native', origin: 'native' });
    assert.deepEqual(settled.errors, []);
    assert.deepEqual(settled.response.result.effects, []);
    assert.equal(settled.state.permission, 'none');
    assert.equal(settled.state.candidate, null);
    await hooks.close();
  });
}
test('neutral decoding forwards unknown envelope metadata without shape interpretation', () => {
  const opaque = { parts: null, body: { ref: 'opaque' }, capabilities: { effects: ['deny'] } };
  const wire = { jsonrpc: '2.0', id: 'event', future: opaque, result: { protocolVersion: 'draft', future: opaque } };
  const snapshot = structuredClone(wire);
  const parsed = validateInterceptResponse(wire);
  assert.equal(parsed.ok, true);
  // Generated JSON extras use null-prototype dictionaries by design.
  assert.equal(JSON.stringify(parsed.value.future), JSON.stringify(opaque));
  assert.equal(JSON.stringify(parsed.value.result.future), JSON.stringify(opaque));
  assert.deepEqual(wire, snapshot);
});

test('effects defaulting does not bypass canonical validation', () => {
  for (const result of [{ protocolVersion: 'wrong' }, { protocolVersion: 'draft', effects: null }, { protocolVersion: 'draft', effects: {} }]) {
    assert.equal(validateInterceptResponse({ jsonrpc: '2.0', id: 'event', result }).ok, false);
  }
});

for (const [type, method, target, facts] of [
  ['context.compact.before', 'contextCompactBefore', 'instructions', { trigger: 'manual', items: [] }],
  ['context.compact.after', 'contextCompactAfter', 'summary', { removed: [], execution: { status: 'executed' } }],
]) test(`${method} accepts flat text edits without inserting message parts or traversing extras`, async () => {
  const opaque = { parts: [{ kind: 'attachment', body: { ref: 'https://private.test/never-read' } }], capabilities: { effects: ['deny'] } };
  const changed = text('new', 'edited');
  const snapshot = structuredClone(changed);
  const hooks = client(type, caps(target), () => ({ effects: [edit(target, [changed])] }));
  const settled = await hooks[method]({ ...facts, native: { test: opaque }, [target]: [text('old', 'old')] });
  assert.deepEqual(settled.event.native, { test: opaque });
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.event[target], [snapshot]);
  assert.equal(Object.hasOwn(settled.event[target][0], 'parts'), false);
  assert.deepEqual(changed, snapshot);
  await hooks.close();
});

test('public message edits preserve text parts and opaque metadata', async () => {
  const changed = message('edited');
  const hooks = client('user.message.inbound', caps('prompt'), () => ({ effects: [edit('prompt', [changed])] }));
  const settled = await hooks.userMessageInbound({ message: { channel: 'chat', sender: 'user', messages: [message('old')] } });
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.event.message.messages, [changed]);
  assert.equal(Object.hasOwn(settled.event.message.messages[0].parts[0], 'parts'), false);
  await hooks.close();
});

test('invalid later response rolls back all its edits while retaining earlier acceptance', async () => {
  const hooks = client('context.compact.before', caps('instructions'), (_, url) => ({ effects: url.includes('backend0')
    ? [edit('instructions', [text('accepted', 'accepted')])]
    : [edit('instructions', [text('unpublished', 'unpublished')]), edit('instructions', [message('wrong-shape')])] }), 2);
  const settled = await hooks.contextCompactBefore({ trigger: 'manual', items: [], instructions: [text('old', 'old')] });
  assert.equal(settled.errors.length, 1);
  assert.deepEqual(settled.event.instructions, [text('accepted', 'accepted')]);
  await hooks.close();
});
for (const reply of [{}, { effects: [] }]) test(`backend helper accepts neutral ${Object.hasOwn(reply, 'effects') ? 'empty' : 'absent'} effects`, async () => {
  const request = { jsonrpc: '2.0', id: 'event', method: 'hooks/intercept', params: { protocolVersion: 'draft', capabilities: { effects: [] }, event: { id: 'event', source: 'urn:test:backend', time: '2026-01-01T00:00:00Z', type: 'tool.before', call: { id: 'call' }, path: 'native', tool: { name: 'read', origin: 'native', input: {} } } } };
  const response = await backendHooks.handle(new Request('https://backend.test/hooks', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request) }), () => reply);
  const wire = await response.json();
  assert.equal(wire.result.protocolVersion, 'draft');
  assert.deepEqual(wire.result.effects ?? [], []);
  assert.deepEqual(reply, Object.hasOwn(reply, 'effects') ? { effects: [] } : {});
});

test('public workspace edit preserves opaque change metadata without attachment traversal', async () => {
  const change = { cwd: '/next' };
  const native = { future: { parts: [{ kind: 'attachment', body: { ref: 'not-a-grant' } }] } };
  const hooks = client('workspace.change.before', caps('workspace'), () => ({ effects: [edit('workspace', change)] }));
  const settled = await hooks.workspaceChangeBefore({ native, workspace: { kind: 'cwd', change: { cwd: '/old' } } });
  assert.deepEqual(settled.event.native, native);
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.event.workspace.change, change);
  await hooks.close();
});

test('public model return retains a canonical whole message list', async () => {
  const value = [message('model', 'assistant')];
  const hooks = client('model.request.before', { effects: ['return'] }, () => ({ effects: [{ type: 'return', value }] }));
  const settled = await hooks.modelRequestBefore({ model: { id: 'model', provider: 'test' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [] });
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.state.candidate.value, value);
  await hooks.close();
});

test('public elicitation return retains a canonical ElicitResult and form answer', async () => {
  const value = { action: 'accept', content: { answer: 'yes' } };
  const hooks = client('user.elicitation.request', { effects: ['return'], elicitation: { form: {} } }, () => ({ effects: [{ type: 'return', value }] }));
  const settled = await hooks.userElicitationRequest({ elicitation: { mode: 'form', server: 'test', request: text('request', JSON.stringify({ message: 'Answer?', requestedSchema: { type: 'object', properties: { answer: { type: 'string' } }, required: ['answer'] } })) } });
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.state.candidate.value, value);
  await hooks.close();
});
