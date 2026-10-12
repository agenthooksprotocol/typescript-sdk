import test from 'node:test';
import assert from 'node:assert/strict';
import { Hooks } from 'agenthooksprotocol/client';

const text = (id, value) => ({ id, kind: 'text', mediaType: 'text/plain', selection: 'body', text: value });
function client(reply) {
  return new Hooks({ protocolVersion: 'draft', hooks: [{
    id: 'test.compaction', transport: { type: 'http', url: 'https://backend.test/hooks' },
    subscriptions: [{ mode: 'intercept', events: ['context.compact.before', 'context.compact.after'], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'body' } }],
  }] }, { source: 'urn:test:compaction', capabilities: {
    contextCompactBefore: {intercept: {returnResult: true}},
    contextCompactAfter: { intercept: { modifySummary: "replace" } },
  }, fetch: async (_url, init) => {
    const request = JSON.parse(init.body);
    return Response.json({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: 'draft', effects: reply(request) } });
  } });
}

// No host-side compatibility conversion: the public orchestrator owns admission.
test('canonical compaction return preserves the complete ordered parts and after summary', async () => {
  const supplied = [text('summary:first', 'first'), text('summary:second', ':second')];
  const hooks = client(request => {
    if (request.params.event.type === 'context.compact.before') return [{ type: 'return', value: supplied }];
    assert.deepEqual(request.params.event.summary, supplied);
    assert.deepEqual(request.params.event.execution, { status: 'skipped', reason: 'supplied_result' });
    return [];
  });
  try {
    const before = await hooks.contextCompactBefore({ trigger: 'manual', items: [], instructions: [text('instructions', 'base')] });
    assert.deepEqual(before.diagnostics.filter(d => d.phase !== 'observation'), []);
    assert.deepEqual(before.state.candidate.value, supplied);
    assert.deepEqual(before.effects, []);
    assert.deepEqual(before.acceptedResponses[0].result.effects, [{ type: 'return', value: supplied }]);
    const after = await hooks.contextCompactAfter({ summary: before.state.candidate.value, removed: [], execution: { status: 'skipped', reason: 'supplied_result' } });
    assert.deepEqual(after.diagnostics.filter(d => d.phase !== 'observation'), []);
    assert.deepEqual(after.event.summary, supplied);
  } finally { await hooks.close(); }
});

for (const value of ['legacy summary', [{ kind: 'text', text: 'incomplete' }]]) {
  test(`canonical compaction rejects ${typeof value === 'string' ? 'string returns' : 'incomplete parts'} atomically`, async () => {
    const hooks = client(() => [{ type: 'return', value }]);
    try {
      const result = await hooks.contextCompactBefore({ trigger: 'manual', items: [], instructions: [text('instructions', 'base')] });
      assert.equal(result.diagnostics.filter(d => d.phase !== 'observation').length, 1);
      assert.equal(result.state.candidate, null);
      assert.deepEqual(result.effects, []);
      assert.deepEqual(result.event.instructions, [text('instructions', 'base')]);
    } finally { await hooks.close(); }
  });
}
