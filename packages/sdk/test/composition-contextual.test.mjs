import test from 'node:test';
import assert from 'node:assert/strict';
import { composeResponse, composeResponseAsync, normalizeEffects } from '../dist/src/client/composition.js';
import { mapParts, localParts } from '../dist/src/client/content-paths.js';

const envelope = type => ({ id: 'event', source: 'urn:test:contextual', time: '2026-01-01T00:00:00Z', type });
const response = effects => ({ jsonrpc: '2.0', id: 'event', result: { protocolVersion: 'draft', ...(effects === undefined ? {} : { effects }) } });
const text = id => ({ id, kind: 'text', mediaType: 'text/plain', selection: 'body', text: id });
const message = id => ({ id, role: 'user', parts: [text(id + '.text')] });
const context = () => ({ ...envelope('context.compact.before'), items: [], instructions: [text('old')], trigger: 'manual' });
const model = () => ({ ...envelope('model.request.before'), call: { id: 'call' }, model: { id: 'model', provider: 'test' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [] });
const options = { readContent: async () => { throw new Error('Unexpected attachment read'); } };

test('originating event selects text and message return contracts', async () => {
  const caps = { effects: ['return'] };
  const texts = composeResponse(context(), [], response([{ type: 'return', value: [text('summary')] }]), caps);
  assert.deepEqual(texts.state.candidate.value, [text('summary')]);
  const messages = await composeResponseAsync(model(), [], response([{ type: 'return', value: [message('candidate')] }]), caps, options);
  assert.deepEqual(messages.state.candidate.value, [message('candidate')]);
  assert.throws(() => composeResponse(context(), [], response([{ type: 'return', value: [message('wrong')] }]), caps), /Invalid intercept response/);
  assert.throws(() => composeResponse(model(), [], response([{ type: 'return', value: [text('wrong')] }]), caps), /Invalid intercept response/);
});

test('known malformed variants reject before any edits are published', async () => {
  const event = context();
  const snapshot = structuredClone(event);
  const caps = { effects: ['modify'], modify: { instructions: { replace: true, merge: true } } };
  await assert.rejects(composeResponseAsync(event, [], response([
    { type: 'modify', target: 'instructions', operation: 'replace', value: [text('new')] },
    { type: 'modify', target: 'instructions', operation: 'merge', value: [{ ...text('bad'), text: 42 }] },
  ]), caps, options), /Invalid intercept response/);
  assert.deepEqual(event, snapshot);
  assert.throws(() => composeResponse(event, [], response([{ type: 'modify', target: 'request', operation: 'replace', value: [] }]), caps), /Invalid intercept response/);
});

test('absent optional effects are empty; null is malformed', async () => {
  const event = context();
  assert.deepEqual(composeResponse(event, [], response(), { effects: [] }).effects, []);
  assert.deepEqual((await composeResponseAsync(event, [], response(), { effects: [] }, options)).effects, []);
  assert.throws(() => composeResponse(event, [], response(null), { effects: [] }), /Invalid intercept response/);
});

test('injection state stores full effects and preserves prior extras', () => {
  const injection = { type: 'inject', target: 'context', operation: 'append', deliverAt: 'next_turn', value: [message('injected')] };
  const previous = { permission: 'none', candidate: { value: [message('old')], provenance: { subscriber: 'first' } }, injections: [injection], extra: { retained: true } };
  const result = normalizeEffects([injection], previous);
  assert.deepEqual(result.state.injections, [injection, injection]);
  assert.deepEqual(result.state.extra, previous.extra);
  assert.deepEqual(result.state.candidate, previous.candidate);
  const replaced = normalizeEffects([{ type: 'return', value: [message('new')] }], previous);
  assert.deepEqual(replaced.state.candidate, { value: [message('new')] });
  assert.deepEqual(previous.candidate.provenance, { subscriber: 'first' });
});

test('canonical validation retains constraints beyond payload selection', () => {
  const event = model();
  assert.throws(() => composeResponse(event, [], response([{ type: 'return', value: [{ id: 'bad', role: 'user', parts: [{ ...text('part'), gap: { reason: 'missing' } }] }] }]), { effects: ['return'] }), /Invalid intercept response/);
});

test('catalogue traversal does not inspect unknown bags or insert absent slots', () => {
  const body = new ReadableStream();
  const reference = { id: 'content', uri: 'urn:content:opaque' };
  const attachment = { id: 'attachment', kind: 'attachment', mediaType: 'image/png', selection: 'body', body };
  const refPart = { ...attachment, id: 'reference', body: reference };
  const unknown = { kind: 'attachment', body };
  const event = { ...envelope('model.request.before'), items: [{ id: 'message', role: 'user', parts: [attachment, refPart] }], native: unknown, params: { items: [unknown] }, extra: { parts: [unknown] } };
  const seen = [];
  const mapped = mapParts(event, (part, path) => { seen.push(path); return { ...part }; });
  assert.equal(seen.length, 2);
  assert.equal(mapped.items[0].parts[0].body, body);
  assert.equal(mapped.items[0].parts[1].body, reference);
  assert.equal(mapped.native, unknown);
  assert.equal(mapped.params, event.params);
  assert.equal(mapped.extra, event.extra);
  assert.deepEqual(localParts({ ...envelope('model.request.before'), items: [{ id: 'message', parts: [{ kind: 'future', parts: [unknown] }] }] }), []);
  const absent = mapParts(envelope('model.request.before'), () => assert.fail('No absent leaves'));
  assert.equal(Object.hasOwn(absent, 'items'), false);
  assert.equal(body.locked, false);
});

test('workspace modifications use the declared object contract', () => {
  const event = { ...envelope('workspace.change.before'), items: [], workspace: { kind: 'cwd', change: { cwd: '/before', workspaceRoots: ['/old'] } } };
  const caps = { effects: ['modify'], modify: { workspace: { replace: true, merge: true } } };
  const edit = value => response([{ type: 'modify', target: 'workspace', operation: 'merge', value }]);
  const result = composeResponse(event, [], edit({ cwd: '/after' }), caps);
  assert.deepEqual(result.event.workspace.change, { cwd: '/after', workspaceRoots: ['/old'] });
  assert.equal(event.workspace.change.cwd, '/before');
  assert.throws(() => composeResponse(event, [], edit({ cwd: 42 }), caps), /Invalid intercept response/);
  assert.throws(() => composeResponse(event, [], edit([]), caps), /Invalid intercept response/);
});

test('canonical event and capability validation preserves exact bigint values', () => {
  const exact = 9007199254740993n;
  const event = { ...model(), params: { exact }, extensions: { 'test.exact': exact } };
  const result = composeResponse(event, [], response([{ type: 'modify', target: 'request', operation: 'replace', value: [message('bigint')] }]), { effects: ['modify'], modify: { request: { replace: true, merge: true } } });
  assert.equal(result.event.params.exact, exact);
  assert.equal(result.event.extensions['test.exact'], exact);
  const turn = { ...envelope('turn.finish.before'), items: [] };
  const continued = composeResponse(turn, [], response([{ type: 'flow', operation: 'continue', instruction: 'continue' }]), { effects: ['flow'], flow: { operations: ['continue'], remainingContinuations: exact, maxContinuations: exact, continuationCount: 0n } });
  assert.equal(continued.state.flow, 'continue');
});


test('declared message returns and injections validate attachment authority, but tool result bags remain opaque', async () => {
  const attachment = { id: 'image', kind: 'attachment', mediaType: 'image/png', selection: 'body', body: { ref: 'https://untrusted.test/image' } };
  const messages = [{ id: 'message', role: 'user', parts: [attachment] }];
  const resolveAttachment = () => { throw new Error('Unauthorized binary attachment'); };
  await assert.rejects(composeResponseAsync(model(), [], response([{ type: 'return', value: messages }]), { effects: ['return'] }, { ...options, resolveAttachment }), /Unauthorized binary/);
  await assert.rejects(composeResponseAsync(model(), [], response([{ type: 'inject', target: 'context', operation: 'append', deliverAt: 'next_turn', value: messages }]), { effects: ['inject'], inject: { context: { append: true, deliverAt: ['next_turn'] } } }, { ...options, resolveAttachment }), /Unauthorized binary/);
  const tool = { ...envelope('tool.before'), call: { id: 'call' }, tool: { name: 'read', input: {} }, origin: 'native', path: 'native', items: [] };
  const accepted = await composeResponseAsync(tool, [], response([{ type: 'return', value: { items: messages } }]), { effects: ['return'] }, { ...options, resolveAttachment });
  assert.deepEqual(accepted.state.candidate.value, { items: messages });
});
