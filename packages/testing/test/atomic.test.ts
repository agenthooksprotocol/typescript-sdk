import test from 'node:test';
import assert from 'node:assert/strict';
import { runAtomicInterop } from '../src/interop/atomic-client.js';

test('draft tool.before atomic responses: exact state, trace and real transport equivalence', async () => {
  const rows = await runAtomicInterop();
  assert.equal(rows.length, 68);
  for (const row of rows) {
    assert.equal(JSON.stringify(row.actual.requests).includes('subscriptionId'), false, row.id);
    assert.deepEqual(row.actual, row.expected, `${row.transport}: ${row.id}`);
    // These assertions also guard against accidental execution/message emission on rejection.
    if (row.actual.actions.includes('blocked') || row.actual.actions.includes('approval-required')) {
      assert.equal(row.actual.trace.includes('execute'), false, row.id);
      assert.equal(row.actual.executions, 0, row.id);
    }
    assert.equal(row.actual.trace.includes('message:hidden'), false, row.id);
    assert.equal(row.actual.emittedMessages.includes('hidden'), false, row.id);
  }
  const http = rows.filter(row => row.transport === 'http');
  const stdio = rows.filter(row => row.transport === 'stdio');
  assert.deepEqual(http.map(row => [row.id, row.actual]), stdio.map(row => [row.id, row.actual]));
});
