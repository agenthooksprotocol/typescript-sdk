import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInterceptRequest, draftCodecs, stageResponse, type Capabilities, type Effect, type PendingState } from '@agenthooksprotocol/sdk/draft';
import { DecisionPipeline, type Interceptor } from '../src/interop/interruption-pipeline.js';
import { openInterruptionTransport } from '../src/interop/interruption-transport.js';

const initial: PendingState = { input: { task: 1 }, candidate: null, permission: 'native', approval: 'not-required', denied: false, messages: [] };
const capabilities: Capabilities = { effects: ['deny', 'allow', 'ask', 'modify', 'message', 'return'], modify: { input: { replace: true, merge: true } } };
function wire(id: string, state: PendingState): string {
  const parsed = parseInterceptRequest(JSON.stringify({ jsonrpc: '2.0', id, method: 'hooks/intercept', params: {
    protocolVersion: 'draft', capabilities, event: { id, source: 'urn:ahp:interruption', type: 'tool.before', time: '2026-01-01T00:00:00Z', session: { id: 'interruption' }, call: {id}, path:'native', tool: {origin:'native', name: 'task', kind: 'task', input: state.input } },
    state: { permission: 'none', candidate: null },
  } }));
  if (!parsed.ok) throw new Error('Invalid test request');
  return draftCodecs.encodeInterceptRequest(parsed.value);
}
const reply = (id: string, effects: Effect[]) => draftCodecs.encodeInterceptResponse({ jsonrpc: '2.0', id, result: { protocolVersion: 'draft', effects } });
function barrier() {
  let resolve!: () => void;
  const promise = new Promise<void>(r => { resolve = r; });
  return { promise, resolve };
}
interface Scenario { id: string; phase: 'pending' | 'accepted' | 'timeout' | 'failure'; failurePolicy: 'fail-open' | 'fail-closed'; effects: Effect[] }
const scenarios: Scenario[] = JSON.parse(readFileSync(new URL('../../interop/interruption-scenarios.json', import.meta.url).pathname, 'utf8')).scenarios;

test('interruption barriers: real HTTP and persistent stdio have identical state and traces', async () => {
  const outcomes: unknown[][] = [];
  for (const kind of ['http', 'stdio'] as const) {
    const transport = await openInterruptionTransport(kind);
    // Persistent stdio permits one outstanding exchange per backend.
    const independent = kind === 'stdio' ? await openInterruptionTransport(kind) : transport;
    const rows: unknown[] = [];
    try {
      for (const scenario of scenarios) {
        const pipeline = new DecisionPipeline(initial);
        const id = scenario.id;
        const exchange = transport.start(id, wire(id, initial), scenario.phase === 'failure' ? '{invalid' : reply(id, scenario.effects));
        const accepted = barrier(), execute = barrier();
        const subscriber: Interceptor = { id, failurePolicy: scenario.failurePolicy, capabilities, start: () => exchange };
        const next: Interceptor = { ...subscriber, id: 'next', start: () => { throw new Error('next subscriber must not run'); } };
        const run = pipeline.run(scenario.phase === 'pending' ? [subscriber, next] : [subscriber], async () => { accepted.resolve(); await execute.promise; });
        await exchange.received;
        if (scenario.phase === 'pending') {
          // Independent request already in flight: cancel must target only the first.
          const otherId = id + '-unrelated';
          const other = independent.start(otherId, wire(otherId, initial), reply(otherId, []));
          await other.received;
          pipeline.interrupt();
          await run; // settles before the backend is released, regardless of failure policy
          await exchange.closed;
          await other.release();
          assert.equal(await other.response, reply(otherId, []));
          await other.closed;
          await exchange.release();
          assert.deepEqual(pipeline.state, initial, id);
          assert.deepEqual(pipeline.trace, [`dispatch:${id}`, 'interrupt', 'interrupted'], id);
          assert.equal(pipeline.failures, 0, id);
          assert.deepEqual(pipeline.messages, [], id);
        } else if (scenario.phase === 'accepted') {
          await exchange.release();
          await accepted.promise;
          pipeline.interrupt();
          execute.resolve();
          await run;
          const expected = stageResponse(initial, scenario.effects, capabilities, id);
          assert.deepEqual(pipeline.state, expected, id);
          assert.deepEqual(pipeline.messages, expected.messages, id);
          assert.deepEqual(pipeline.trace, [`dispatch:${id}`, `accept:${id}`, ...expected.messages.map(m => `message:${m}`), 'interrupt', 'interrupted'], id);
        } else {
          if (scenario.phase === 'timeout') pipeline.expire();
          else await exchange.release();
          await accepted.promise;
          execute.resolve();
          await run;
          if (scenario.phase === 'timeout') { await exchange.closed; await exchange.release(); }
          assert.equal(pipeline.interrupted, false, id);
          assert.equal(pipeline.failures, 1, id);
          assert.deepEqual(pipeline.state, { ...initial, denied: scenario.failurePolicy === 'fail-closed' }, id);
          assert.deepEqual(pipeline.trace, [`dispatch:${id}`, `reject:${id}`, scenario.phase === 'timeout' ? 'timeout' : 'backend-failure', `failure:${scenario.failurePolicy}`, 'policy', scenario.failurePolicy === 'fail-open' ? 'execute' : 'blocked'], id);
          assert.deepEqual(pipeline.messages, [], id);
        }
        assert.equal(pipeline.executions, (scenario.phase === 'timeout' || scenario.phase === 'failure') && scenario.failurePolicy === 'fail-open' ? 1 : 0, id);
        await exchange.closed;
        // Reuse the transport for a genuinely new operation, not only a raw echo.
        const freshId = id + '-fresh';
        const fresh = new DecisionPipeline(initial);
        const freshExchange = transport.start(freshId, wire(freshId, initial), reply(freshId, []));
        const freshRun = fresh.run([{ ...subscriber, id: freshId, start: () => freshExchange }]);
        await freshExchange.received; await freshExchange.release(); await freshRun; await freshExchange.closed;
        assert.equal(fresh.executions, 1);
        assert.equal(fresh.failures, 0);
        rows.push({ id, state: pipeline.state, trace: pipeline.trace, messages: pipeline.messages, failures: pipeline.failures, executions: pipeline.executions });
      }
    } finally {
      await transport.dispose();
      if (independent !== transport) await independent.dispose();
    }
    outcomes.push(rows);
  }
  assert.equal(scenarios.length, 13);
  assert.deepEqual(outcomes[0], outcomes[1]);
});

test('interruption before dispatch prevents all subscribers and execution', async () => {
  const pipeline = new DecisionPipeline(initial);
  pipeline.interrupt();
  await pipeline.run([{ id: 'never', failurePolicy: 'fail-open', capabilities, start: () => { throw new Error('unexpected dispatch'); } }]);
  assert.deepEqual(pipeline.trace, ['interrupt', 'interrupted']);
  assert.deepEqual(pipeline.state, initial);
  assert.equal(pipeline.executions, 0);
});

test('delivered but unaccepted compound response cannot survive interruption', async () => {
  for (const failurePolicy of ['fail-open', 'fail-closed'] as const) {
    const pipeline = new DecisionPipeline(initial);
    let deliver!: (body: string) => void;
    let cancellations = 0;
    const response = new Promise<string>(resolve => { deliver = resolve; });
    const run = pipeline.run([
      { id: 'queued', failurePolicy, capabilities, start: () => ({ response, cancel: () => { cancellations++; } }) },
      { id: 'never', failurePolicy, capabilities, start: () => { throw new Error('unexpected dispatch'); } },
    ]);
    deliver(reply('queued', [
      { type: 'modify', target: 'input', operation: 'merge', value: { task: 2 } },
      { type: 'message', text: 'unaccepted' },
      { type: 'return', value: 'unaccepted' },
    ]));
    // Do not yield: the acceptance continuation is queued, not yet committed.
    pipeline.interrupt();
    await run;
    assert.deepEqual(pipeline.state, initial);
    assert.deepEqual(pipeline.messages, []);
    assert.deepEqual(pipeline.trace, ['dispatch:queued', 'interrupt', 'interrupted']);
    assert.equal(pipeline.executions, 0);
    assert.equal(pipeline.failures, 0);
    assert.equal(cancellations, 1);
  }
});

test('cancelled stdio backend can be disposed and replaced without a reply', async () => {
  const old = await openInterruptionTransport('stdio');
  const pipeline = new DecisionPipeline(initial);
  try {
    const exchange = old.start('abandoned', wire('abandoned', initial), reply('abandoned', [{ type: 'allow' }]));
    const run = pipeline.run([{ id: 'abandoned', failurePolicy: 'fail-open', capabilities, start: () => exchange }]);
    await exchange.received;
    pipeline.interrupt();
    await run;
    await exchange.closed;
    // No release, no backend response acknowledgement, no outstanding waiter.
  } finally { await old.dispose(); }
  const replacement = await openInterruptionTransport('stdio');
  try {
    const fresh = new DecisionPipeline(initial);
    const exchange = replacement.start('new-process', wire('new-process', initial), reply('new-process', []));
    const run = fresh.run([{ id: 'new-process', failurePolicy: 'fail-closed', capabilities, start: () => exchange }]);
    await exchange.received; await exchange.release(); await run; await exchange.closed;
    assert.equal(fresh.executions, 1);
    assert.equal(fresh.failures, 0);
    assert.equal(pipeline.executions, 0);
  } finally { await replacement.dispose(); }
});

test('synchronous interruption during start cancels exactly once without awaiting a response', async () => {
  for (const failurePolicy of ['fail-open', 'fail-closed'] as const) {
    const pipeline = new DecisionPipeline(initial);
    let cancellations = 0;
    let rejectResponse!: (reason: Error) => void;
    const response = new Promise<string>((_, reject) => { rejectResponse = reject; });
    await pipeline.run([
      {id: 'synchronous', failurePolicy, capabilities, start: () => {
        pipeline.interrupt();
        return {response, cancel: () => {
          cancellations++;
          pipeline.interrupt(); // Reentrant cancellation must not cancel twice.
          pipeline.expire();
        }};
      }},
      {id: 'never', failurePolicy, capabilities, start: () => { throw new Error('unexpected dispatch'); }},
    ]);
    pipeline.interrupt();
    pipeline.expire();
    rejectResponse(new Error('late backend failure')); // Must be observed, not unhandled.
    await Promise.resolve();
    assert.equal(cancellations, 1);
    assert.equal(pipeline.executions, 0);
    assert.equal(pipeline.failures, 0);
    assert.deepEqual(pipeline.state, initial);
    assert.deepEqual(pipeline.messages, []);
    assert.deepEqual(pipeline.trace, ['dispatch:synchronous', 'interrupt', 'interrupted']);
  }
});

test('interruption during native pre-execution callback wins without undoing accepted changes',async()=>{
 for(const reentrant of [true,false]){
  const pipeline=new DecisionPipeline(initial),entered=barrier(),release=barrier();
  const effects:Effect[]=[{type:'modify',target:'input',operation:'merge',value:{task:2}},{type:'return',value:'accepted candidate'},{type:'message',text:'accepted message'}];
  const run=pipeline.run([{id:'accepted',failurePolicy:'fail-open',capabilities,start:()=>({response:Promise.resolve(reply('accepted',effects)),cancel:()=>{throw Error('Nothing pending');}})}],async()=>{
   entered.resolve();
   if(reentrant)pipeline.interrupt();else await release.promise;
  });
  await entered.promise;
  if(!reentrant){pipeline.interrupt();release.resolve();}
  await run;
  assert.equal(pipeline.interrupted,true);assert.equal(pipeline.executions,0);assert.equal(pipeline.failures,0);
  assert.equal(pipeline.state.input.task,2);assert.equal(pipeline.state.candidate?.value,'accepted candidate');
  assert.deepEqual(pipeline.messages,['accepted message']);assert.equal(pipeline.trace.at(-1),'interrupted');
  assert.equal(pipeline.trace.some(entry=>entry.startsWith('candidate:')),false);
 }
});
