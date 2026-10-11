import test from 'node:test';
import assert from 'node:assert/strict';
import { composeResponse, composeResponseAsync } from '../dist/src/client/composition.js';

const text = (id, value) => ({ id, kind: 'text', mediaType: 'text/plain', selection: 'body', text: value });
const message = (id, role = 'user') => ({ id, role, parts: [text(`${id}.text`, id)] });
const envelope = (type) => ({ id: 'event', source: 'urn:test:inline', time: '2026-01-01T00:00:00Z', type });
const response = (...effects) => ({ jsonrpc: '2.0', id: 'request', result: { protocolVersion: 'draft', effects } });
const edit = (target, operation, value) => ({ type: 'modify', target, operation, value });
const capabilities = (target) => ({ effects: ['modify'], modify: { [target]: { replace: true, merge: true } } });
const options = { readContent: async () => { throw new Error('Attachments must not be read'); } };

for (const [type, target, role] of [
  ['user.message.inbound', 'prompt', 'user'],
  ['user.message.outbound', 'content', 'assistant'],
]) {
  test(`${type}: replace substitutes and merge appends duplicates in serial order`, async () => {
    const event = { ...envelope(type), message: { channel: 'chat', ...(role === 'user' ? { sender: 'user' } : {}), messages: [message('old', role)] } };
    const next = message('next', role);
    const first = composeResponse(event, [], response(edit(target, 'replace', [next])), capabilities(target));
    const second = await composeResponseAsync(first.event, first.effects, response(edit(target, 'merge', [next, message('last', role)])), capabilities(target), options);
    assert.deepEqual(second.event.message.messages.map(m => m.id), ['next', 'next', 'last']);
    assert.deepEqual(event.message.messages.map(m => m.id), ['old']);
  });
}

for (const [type, target, extra] of [
  ['context.compact.before', 'instructions', { items: [], trigger: 'manual' }],
  ['context.compact.after', 'summary', { removed: [], execution: { status: 'executed' } }],
]) {
  test(`${type}: ordered inline text lists`, async () => {
    const event = { ...envelope(type), ...extra, [target]: [text('old', 'old')] };
    const result = await composeResponseAsync(event, [], response(edit(target, 'replace', [text('new', 'new')]), edit(target, 'merge', [text('new', 'new')])), capabilities(target), options);
    assert.deepEqual(result.event[target].map(p => p.text), ['new', 'new']);
    assert.equal(event[target][0].text, 'old');
  });
}

test('model request edits canonical messages, not provider params', () => {
  const event = { ...envelope('model.request.before'), call: { id: 'call' }, model: { id: 'model', provider: 'test' }, attempt: { id: "attempt", number: 1 }, params: { temperature: 0.3 }, items: [] };
  const result = composeResponse(event, [], response(edit('request', 'replace', [message('request')])), capabilities('request'));
  assert.deepEqual(result.event.items, [message('request')]);
  assert.deepEqual(result.event.params, event.params);
});

test('attachments are preserved without reading or rewriting binary streams', async () => {
  const body = new ReadableStream({ pull() { throw new Error('Unexpected binary read'); } });
  const event = { ...envelope('user.message.inbound'), message: { channel: 'chat', sender: 'user', messages: [{ id: 'binary', role: 'user', parts: [{ id: 'image', kind: 'attachment', mediaType: 'image/png', selection: 'body', body }] }] } };
  const result = await composeResponseAsync(event, [], response(edit('prompt', 'merge', [message('new')])), capabilities('prompt'), options);
  assert.equal(result.event.message.messages[0].parts[0].body, body);
  assert.equal(body.locked, false);
});

test('a later invalid role rejects the whole response without changing the source', async () => {
  const event = { ...envelope('user.message.inbound'), message: { channel: 'chat', sender: 'user', messages: [message('old')] } };
  const snapshot = structuredClone(event);
  await assert.rejects(composeResponseAsync(event, [], response(edit('prompt', 'replace', [message('new')]), edit('prompt', 'merge', [message('wrong', 'assistant')])), capabilities('prompt'), options));
  assert.deepEqual(event, snapshot);
});

test('object targets merge shallowly, retaining null and replacing nested objects', () => {
  const event = { ...envelope('tool.before'), call: { id: 'call' }, tool: { name: 'tool', origin: 'native', input: { nested: { a: 1, b: 2 }, retained: true, nullable: 1 } }, path: "/tool" };
  const result = composeResponse(event, [], response(edit('input', 'merge', { nested: { b: 3 }, nullable: null })), capabilities('input'));
  assert.deepEqual(result.event.tool.input, { nested: { b: 3 }, retained: true, nullable: null });
  assert.equal(event.tool.input.nested.a, 1);
});

 test('no-op inline replacement retains decisions; changed content invalidates them', () => {
  const event = { ...envelope('user.message.inbound'), message: { channel: 'chat', sender: 'user', messages: [message('old')] } };
  const previous = [{ type: 'allow' }, { type: 'return', value: 'candidate' }];
  const noop = composeResponse(event, previous, response(edit('prompt', 'replace', [message('old')])), capabilities('prompt'));
  assert.ok(noop.effects.some(e => e.type === 'allow'));
  assert.ok(noop.effects.some(e => e.type === 'return'));
  const changed = composeResponse(event, previous, response(edit('prompt', 'replace', [message('new')])), capabilities('prompt'));
  assert.ok(!changed.effects.some(e => e.type === 'allow' || e.type === 'return'));
});

test('elicitation answer content requires an object, not an ordinary message list', async () => {
  const event = {
    ...envelope('user.elicitation.result'), parentEventId: 'request',
    elicitation: { mode: 'form', server: 'test', action: 'accept', result: text('answer', JSON.stringify({ action: 'accept', content: {} })) },
  };
  await assert.rejects(composeResponseAsync(event, [], response(edit('content', 'replace', [message('not-an-answer')])), {
    ...capabilities('content'), elicitation: { form: {} },
  }, options), /Invalid intercept response/);
});

test('ordinary model request targets reject objects even when specialized schemas permit them', () => {
  const event = { ...envelope('model.request.before'), call: { id: 'call' }, model: { id: 'model', provider: 'test' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [] };
  assert.throws(() => composeResponse(event, [], response(edit('request', 'replace', { messages: [] })), capabilities('request')));
  assert.deepEqual(event.items, []);
});
