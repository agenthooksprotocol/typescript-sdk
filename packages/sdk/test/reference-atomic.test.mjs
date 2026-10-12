import test from 'node:test';
import assert from 'node:assert/strict';
import { reference } from 'agenthooksprotocol/draft';

const capabilities = { effects: ['modify', 'return'], modify: { input: { replace: true, merge: true } } };
const modification = task => ({ type: 'modify', target: 'input', operation: 'merge', value: { task } });
const initial = () => ({ input: { task: 1 }, candidate: null, permission: 'native', approval: 'not-required', denied: false, messages: [] });

test('synthetic atomic evaluator cannot repair an invalid intermediate edit or publish failed response data', () => {
  const accepted = reference.stageResponse(initial(), [{ type: 'return', value: 'accepted' }], capabilities, 'first');
  const before = structuredClone(accepted);
  assert.throws(() => reference.stageResponse(accepted, [modification(0), modification(2), { type: 'return', value: 'rejected' }], capabilities, 'second'), /Invalid effective tool input/);
  assert.deepEqual(accepted, before);
  const next = reference.stageResponse(accepted, [modification(2)], capabilities, 'third');
  assert.equal(next.input.task, 2);
  assert.equal(next.candidate, null);
});

test('SDK root does not expose the legacy compaction pathway', async () => {
  const root = await import('agenthooksprotocol');
  for (const name of ['runCompaction', 'compactionCapabilities']) {
    assert.equal(Object.hasOwn(root, name), false, `${name} must not be exported`);
  }
});
