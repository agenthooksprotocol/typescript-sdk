import test from 'node:test';
import assert from 'node:assert/strict';
import { Hooks } from '../dist/src/client/index.js';
import { decodeSettledEvent, decodeSettledState } from '../dist/src/client/settlement.js';

const hooksFor = (type, replies = [{}]) => new Hooks({ protocolVersion: 'draft', hooks: replies.map((_, index) => ({
  id: `settlement.backend${index}`, transport: { type: 'http', url: `https://backend${index}.test/hooks` },
  subscriptions: [{ mode: 'intercept', events: [type], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'metadata' } }],
})) }, {
  source: 'urn:test:settlement', capabilities: { [type]: { effects: [] } },
  fetch: async (url, init) => {
    const index = Number(new URL(url).hostname.match(/backend(\d+)/)[1]);
    const reply = replies[index];
    return Response.json({ jsonrpc: '2.0', id: JSON.parse(init.body).id, ...reply,
      result: { protocolVersion: 'draft', ...reply.result } });
  },
});
const text = { kind: 'text', mediaType: 'text/plain', id: 'text', selection: 'body', text: 'hello' };
const json = value => JSON.parse(JSON.stringify(value));

test('decoded generated effective events and canonical state retain opaque extras and complete injection envelopes', async () => {
  const hooks = hooksFor('model.request.before');
  const extra = { parts: null, capabilities: { effects: ['not-authority'] }, nested: [null, { type: 'future' }] };
  const message = { id: 'message', role: 'assistant', parts: [text] };
  const injection = { type: 'inject', target: 'context', operation: 'append', deliverAt: 'next_turn', value: [message] };
  try {
    const settled = await hooks.modelRequestBefore({
      model: { provider: 'test', id: 'model' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [message], extensions: { 'test.future': extra },
    }, { initialState: {
      candidate: { value: [message], provenance: { supplier: 'cache', future: extra }, future: extra },
      permission: 'none', injections: [injection], future: extra,
    } });
    assert.equal(settled.settledEvent.type, 'model.request.before');
    assert.deepEqual(json(settled.settledEvent.extensions['test.future']), extra);
    assert.deepEqual(settled.state.candidate, { value: [message], provenance: { supplier: 'cache', future: extra }, future: extra });
    assert.deepEqual(settled.state.injections, [injection]);
    assert.deepEqual(settled.state.future, extra);
    assert.equal(Object.isFrozen(settled.state.candidate.future), true);
  } finally { await hooks.close(); }
});

test('origin-correlated candidate rejects an otherwise valid generic tool value, including supplied null', async () => {
  const hooks = hooksFor('model.request.before');
  try {
    for (const value of [null, { tool: 'not messages' }]) {
      await assert.rejects(hooks.modelRequestBefore({ model: { provider: 'test', id: 'model' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [] }, {
        initialState: { candidate: { value }, permission: 'allow' },
      }), error => error.code === 'INVALID_CONFIGURATION' || /Invalid origin-correlated settlement candidate/.test(error.message));
    }
    const settled = await hooks.modelRequestBefore({ model: { provider: 'test', id: 'model' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [] });
    assert.equal(settled.state.candidate, null);
  } finally { await hooks.close(); }
});

test('tool supplied null remains a candidate, not absence, with provenance and extras intact', async () => {
  const hooks = hooksFor('tool.before');
  try {
    const candidate = { value: null, provenance: { supplier: 'cache' }, future: { nullable: null } };
    const settled = await hooks.toolBefore({ callId: 'call', name: 'read', input: {}, path: 'native', origin: 'native' }, {
      initialState: { candidate, permission: 'none' },
    });
    assert.deepEqual(settled.state.candidate, candidate);
  } finally { await hooks.close(); }
});

test('invalid decoded settlement events and complete state fail closed instead of returning authority', () => {
  const event = { type: 'model.request.before', id: 'event', time: '2026-01-01T00:00:00Z', source: 'urn:test:settlement', model: { provider: 'test', id: 'model' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [] };
  assert.throws(() => decodeSettledEvent({ ...event, items: [{ id: 'message', role: 'assistant', parts: [{ kind: 'text', selection: 'body', text: 42 }] }] }), /Invalid decoded settlement event/);
  const decoded = decodeSettledEvent(event);
  assert.throws(() => decodeSettledState(decoded, { candidate: null, permission: 'allow', injections: [{ type: 'inject', value: [] }] }), /Invalid decoded settlement state/);
});

test('acceptedResponses retains complete canonical envelopes in order, excluding rejected responses', async () => {
  const opaque = { type: 'future', parts: [null], body: { ref: 'opaque' } };
  const hooks = hooksFor('tool.before', [
    { future: opaque, result: { future: opaque } },
    { result: { protocolVersion: 'invalid' } },
    { future: { order: 3 }, result: { effects: [], future: opaque } },
  ]);
  try {
    const settled = await hooks.toolBefore({ callId: 'call', name: 'read', input: {}, path: 'native', origin: 'native' });
    assert.equal(settled.errors.length, 1);
    assert.equal(settled.acceptedResponses.length, 2);
    assert.deepEqual(json(settled.acceptedResponses[0].future), opaque);
    assert.deepEqual(json(settled.acceptedResponses[0].result.future), opaque);
    assert.equal(Object.hasOwn(settled.acceptedResponses[0].result, 'effects'), false);
    assert.deepEqual(json(settled.acceptedResponses[1].future), { order: 3 });
    assert.deepEqual(settled.acceptedResponses[1].result.effects, []);
    assert.equal(Object.isFrozen(settled.acceptedResponses[0].result.future), true);
    assert.deepEqual(settled.response.result.effects, []);
  } finally { await hooks.close(); }
});

test('public final decode failure throws without authorization and preserves accepted canonical evidence', async () => {
  const input = { model: { provider: 'test', id: 'model' }, attempt: { id: 'attempt', number: 1 }, params: {}, items: [] };
  const hooks = new Hooks({ protocolVersion: 'draft', hooks: [{
    id: 'settlement.backend', transport: { type: 'http', url: 'https://backend.test/hooks' },
    subscriptions: [{ mode: 'intercept', events: ['model.request.before'], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'metadata' } }, { mode: 'observe', events: ['model.request.before'], content: { default: 'metadata' } }],
  }] }, {
    source: 'urn:test:settlement', capabilities: { 'model.request.before': { modes: ['intercept', 'observe'], capabilities: { effects: [] } } },
    fetch: async (_, init) => {
      // Simulate invalid host-owned schema facts after admission. The neutral
      // receiver response is still canonical acceptance evidence, not authority.
      if (JSON.parse(init.body).method === 'hooks/observe') {
        input.model.id = 42;
        return new Response(null, { status: 204 });
      }
      return Response.json({ jsonrpc: '2.0', id: JSON.parse(init.body).id, result: { protocolVersion: 'draft', effects: [] } });
    },
  });
  try {
    await assert.rejects(hooks.modelRequestBefore(input), error => {
      assert.equal(error.code, 'INVALID_SETTLEMENT');
      assert.equal(error.acceptedResponses.length, 1);
      assert.deepEqual(error.acceptedResponses[0].result.effects, []);
      assert.equal(error.permission, undefined);
      return true;
    });
  } finally { await hooks.close(); }
});

test('raw pre-cancelled retirement remains compatible but its typed view and named boundary fail closed', async () => {
  const hooks = hooksFor('tool.before');
  try {
    const raw = await hooks.dispatch('session.end', { session: { id: 'retired' } }, { signal: AbortSignal.abort() });
    assert.equal(raw.interrupted, true);
    assert.deepEqual(raw.acceptedResponses, []);
    assert.throws(() => raw.settledEvent, error => error.code === 'INVALID_SETTLEMENT');
    await assert.rejects(hooks.sessionEnd({ session: { id: 'retired' } }, { signal: AbortSignal.abort() }), error => error.code === 'INVALID_SETTLEMENT');
  } finally { await hooks.close(); }
});
