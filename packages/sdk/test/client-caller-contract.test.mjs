import test from 'node:test';
import assert from 'node:assert/strict';
import { Hooks, Type, contract } from 'agenthooksprotocol/client';

const argsSchema = Type.Object({ count: Type.Integer({ minimum: 0 }), retained: Type.Boolean(), nullable: Type.Union([Type.String(), Type.Null()]), nested: Type.Object({ next: Type.Integer(), old: Type.Optional(Type.Integer()) }) });
const args = contract(argsSchema, value => { if (value.count > value.nested.next) throw Error('count must not exceed next'); });
const result = contract(Type.Object({ answer: Type.String() }));
const facts = input => ({ callId: 'call', name: 'read', input, path: 'native', origin: 'native' });
const initial = () => ({ count: 1, retained: true, nullable: 'old', nested: { next: 8, old: 2 } });
const modify = value => ({ type: 'modify', target: 'input', operation: 'merge', value });
const returned = value => ({ type: 'return', value });
function client(replies, seen = [], type = 'tool.before', caps = { effects: ['modify', 'return'], modify: { input: { replace: true, merge: true } } }) {
  return new Hooks({ protocolVersion: 'draft', hooks: replies.map((_, index) => ({ id: `test.contract.backend${index}`, transport: { type: 'http', url: `https://backend${index}.test/hooks` }, subscriptions: [{ mode: 'intercept', events: [type], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'metadata' }, includeNative: true }] })) }, {
    source: 'urn:test:contracts', capabilities: { [type]: caps }, fetch: async (url, init) => {
      const request = JSON.parse(init.body); seen.push(request);
      const index = Number(String(url).match(/backend(\d+)/)[1]);
      return Response.json({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: 'draft', effects: replies[index] } });
    },
  });
}

test('caller contract implementation helpers are absent from the public client facade', async () => {
  const client = await import('agenthooksprotocol/client');
  for (const name of ['admitContracts', 'encodeContract', 'freezeContractValue', 'decodeContract']) {
    assert.equal(Object.hasOwn(client, name), false);
  }
});

test('a partial merge validates the whole T, preserves omitted fields/null and replaces nested values', async () => {
  const hooks = client([[modify({ count: 3, nullable: null, nested: { next: 9 } })]]);
  const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args, result } });
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.input, { count: 3, retained: true, nullable: null, nested: { next: 9 } });
  await hooks.close();
});

test('invalid full staged T applies none and later receivers only see prior accepted valid state', async () => {
  const seen = [];
  const hooks = client([[modify({ count: 2 }), returned({ answer: 'accepted' })], [returned({ answer: 'unpublished' }), modify({ count: 100 })], []], seen);
  const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args, result } });
  assert.equal(settled.errors.length, 1);
  assert.equal(settled.input.count, 2);
  assert.deepEqual(settled.state.candidate.value, { answer: 'accepted' });
  assert.equal(seen[2].params.event.tool.input.count, 2);
  assert.deepEqual(seen[2].params.state.candidate.value, { answer: 'accepted' });
  assert.equal(seen[2].params.event.tool.input.nested.next, 8);
  await hooks.close();
});

test('Result is independent of Arguments and invalid later return rolls back its entire response', async () => {
  const seen = [];
  const hooks = client([[returned({ answer: 'accepted' })], [modify({ count: 2 }), returned(initial())], []], seen);
  const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args, result } });
  assert.equal(settled.errors.length, 1);
  assert.equal(settled.input.count, 1);
  assert.deepEqual(settled.state.candidate.value, { answer: 'accepted' });
  assert.equal(seen[2].params.event.tool.input.count, 1);
  await hooks.close();
});

test('every return in a response validates, even a candidate superseded by a later return', async () => {
  const hooks = client([[returned({ answer: 1 }), returned({ answer: 'valid-last' })]]);
  const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args, result } });
  assert.equal(settled.errors.length, 1);
  assert.equal(settled.state.candidate, null);
  await hooks.close();
});

test('candidate absence differs from a declared nullable candidate value', async () => {
  const hooks = client([[returned(null)]]);
  const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args, result: contract(Type.Union([Type.String(), Type.Null()])) } });
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.state.candidate, { value: null });
  await hooks.close();
});

test('provenance associates with the initial candidate and clears on replacement', async () => {
  const provenance = contract(Type.Object({ supplier: Type.String() }));
  const state = { permission: 'none', candidate: { value: { answer: 'cached' }, provenance: { supplier: 'cache' } } };
  const neutral = client([[]]);
  const first = await neutral.toolBefore(facts(initial()), { initialState: state, contracts: { arguments: args, result, provenance } });
  assert.deepEqual(first.errors, []);
  assert.deepEqual(first.state.candidate.provenance, { supplier: 'cache' });
  await neutral.close();
  const replacing = client([[returned({ answer: 'new' })]]);
  const second = await replacing.toolBefore(facts(initial()), { initialState: state, contracts: { arguments: args, result, provenance } });
  assert.deepEqual(second.errors, []);
  assert.deepEqual(second.state.candidate, { value: { answer: 'new' } });
  await replacing.close();
});

test('initial caller input and initial candidate validate before any receiver sees them', async () => {
  const seen = [];
  const hooks = client([[]], seen);
  await assert.rejects(hooks.toolBefore(facts({ ...initial(), count: 99 }), { contracts: { arguments: args } }));
  await assert.rejects(hooks.toolBefore(facts(initial()), { contracts: { result }, initialState: { permission: 'none', candidate: { value: { answer: 9 } } } }));
  assert.equal(seen.length, 0);
  await hooks.close();
});

test('unknown argument fields remain opaque; codecs that drop them are rejected at admission', async () => {
  const input = { ...initial(), future: { parts: null, body: { ref: 'not-a-grant' } } };
  const hooks = client([[modify({ count: 2 })]]);
  const settled = await hooks.toolBefore(facts(input), { contracts: { arguments: args } });
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.input.future, input.future);
  await hooks.close();
  const dropping = { decode: value => ({ count: value.count }), encode: value => value };
  const rejecting = client([[]]);
  await assert.rejects(rejecting.toolBefore(facts(input), { contracts: { arguments: dropping } }), /preserve all JSON data/);
  await rejecting.close();
});

test('explicit opaque host slot codecs validate provider/native facts; absent codecs do not interpret shapes', async () => {
  const native = { count: 1, parts: null };
  const seen = [];
  const hooks = client([[]], seen, 'model.request.before', { effects: [] });
  const input = { model: { id: 'model', provider: 'test' }, attempt: { id: 'attempt', number: 1 }, params: { temperature: 0.5 }, items: [], native };
  const contracts = { payloads: [{ path: ['params'], codec: contract(Type.Object({ temperature: Type.Number({ maximum: 1 }) })) }, { path: ['native'], codec: contract(Type.Object({ count: Type.Integer() })) }] };
  const settled = await hooks.modelRequestBefore(input, { contracts });
  assert.deepEqual(settled.errors, []);
  assert.deepEqual(settled.event.native, native);
  await assert.rejects(hooks.modelRequestBefore({ ...input, params: { temperature: 2 } }, { contracts }));
  assert.equal(seen.length, 1);
  await hooks.close();
});

test('contract rejects unsupported Ajv keywords and enforces constraints without coercion/default insertion', () => {
  assert.throws(() => contract(Type.String({ inventedKeyword: true })));
  const codec = contract(Type.Object({ count: Type.Integer({ minimum: 1, default: 1 }) }));
  assert.throws(() => codec.decode({}));
  assert.throws(() => codec.decode({ count: '1' }));
  assert.throws(() => codec.decode({ count: 0 }));
});
test('type-invalid partial input never reaches a later interceptor', async () => {
  const seen = [];
  const hooks = client([[modify({ count: '2' })], []], seen);
  const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args } });
  assert.equal(settled.errors.length, 1);
  assert.equal(seen[1].params.event.tool.input.count, 1);
  assert.equal(settled.input.count, 1);
  await hooks.close();
});

test('structural codecs encode host types and decode accepted values without losing wire extras', async () => {
  const dates = { decode(value) { if (typeof value.at !== 'string') throw Error('date'); return new Date(value.at); }, encode(value) { return { at: value.toISOString() }; } };
  const seen = [];
  const date = new Date('2026-01-01T00:00:00Z');
  const hooks = client([[returned({ answer: 'typed-result' })]], seen);
  const settled = await hooks.toolBefore(facts(date), { contracts: { arguments: dates, result } });
  assert.deepEqual(settled.errors, []);
  assert.equal(settled.input.toISOString(), date.toISOString());
  assert.deepEqual(seen[0].params.event.tool.input, { at: date.toISOString() });
  assert.deepEqual(settled.state.candidate.value, { answer: 'typed-result' });
  assert.equal(Object.isFrozen(settled.state.candidate.value), true);
  await hooks.close();
  const strippingEncoder = { decode: value => value, encode: value => ({ count: value.count }) };
  const rejecting = client([[]]);
  await assert.rejects(rejecting.toolBefore(facts(initial()), { contracts: { arguments: strippingEncoder } }), /preserve all JSON data/);
  await rejecting.close();
});

test('public schema inference declarations keep argument/result/provenance and form types distinct', async () => {
  const { spawnSync } = await import('node:child_process');
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const checked = spawnSync(process.execPath, [require.resolve('typescript/bin/tsc'), '--noEmit', '--strict', '--exactOptionalPropertyTypes', '--noUncheckedIndexedAccess', '--target', 'ES2022', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', '--lib', 'ES2022,DOM', '--skipLibCheck', 'packages/sdk/test/client-caller-contract-types.ts', 'node-shims.d.ts'], { encoding: 'utf8', timeout: 30000 });
  assert.equal(checked.status, 0, checked.stdout + checked.stderr);
});


test('an invalid intermediate argument cannot be repaired by a later modification', async () => {
  const hooks = client([[modify({ count: -1 }), modify({ count: 2 })]]);
  try {
    const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args, result } });
    assert.equal(settled.errors.length, 1);
    assert.deepEqual(settled.input, initial());
  } finally { await hooks.close(); }
});

test('invalid then repaired arguments roll back the response and preserve earlier accepted input and candidate', async () => {
  const seen = [];
  const hooks = client([[modify({ count: 2 }), returned({ answer: 'accepted' })], [returned({ answer: 'unpublished' }), modify({ count: -1 }), modify({ count: 3 })], []], seen);
  try {
    const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args, result } });
    assert.equal(settled.errors.length, 1);
    assert.equal(settled.input.count, 2);
    assert.deepEqual(settled.state.candidate, { value: { answer: 'accepted' } });
    assert.equal(seen[2].params.event.tool.input.count, 2);
    assert.deepEqual(seen[2].params.state.candidate, { value: { answer: 'accepted' } });
  } finally { await hooks.close(); }
});

test('an invalid intermediate response preserves prior candidate provenance for the next interceptor', async () => {
  const seen = [];
  const state = { permission: 'none', candidate: { value: { answer: 'cached' }, provenance: { supplier: 'cache' } } };
  const provenance = contract(Type.Object({ supplier: Type.String() }));
  const hooks = client([[], [modify({ count: -1 }), modify({ count: 2 }), returned({ answer: 'unpublished' })], []], seen);
  try {
    const settled = await hooks.toolBefore(facts(initial()), { initialState: state, contracts: { arguments: args, result, provenance } });
    assert.equal(settled.errors.length, 1);
    assert.deepEqual(settled.input, initial());
    assert.deepEqual(settled.state.candidate, state.candidate);
    assert.deepEqual(seen[2].params.event.tool.input, initial());
    assert.deepEqual(seen[2].params.state.candidate, state.candidate);
  } finally { await hooks.close(); }
});


test('caller invariants reject an intermediate argument even when the next merge repairs it', async () => {
  const hooks = client([[modify({ count: 9 }), modify({ count: 2 })]]);
  try {
    const settled = await hooks.toolBefore(facts(initial()), { contracts: { arguments: args } });
    assert.equal(settled.errors.length, 1);
    assert.deepEqual(settled.input, initial());
  } finally { await hooks.close(); }
});

test('explicit host payload codec paths validate each completed temporary modification', async () => {
  const seen = [];
  const hooks = client([[modify({ count: -1 }), modify({ count: 2 })], []], seen);
  try {
    const settled = await hooks.toolBefore(facts(initial()), { contracts: { payloads: [{ path: ['tool', 'input'], codec: args }] } });
    assert.equal(settled.errors.length, 1);
    assert.deepEqual(settled.input, initial());
    assert.deepEqual(seen[1].params.event.tool.input, initial());
  } finally { await hooks.close(); }
});

test('structural host argument codecs reject invalid temporary representations before repair', async () => {
  const dates = {
    decode(value) {
      if (typeof value.at !== 'string') throw Error('date');
      const decoded = new Date(value.at);
      if (!Number.isFinite(decoded.getTime())) throw Error('date');
      return decoded;
    },
    encode(value) { return { at: value.toISOString() }; },
  };
  const seen = [];
  const initialDate = new Date('2026-01-01T00:00:00Z');
  const hooks = client([[modify({ at: 'invalid' }), modify({ at: '2026-02-01T00:00:00.000Z' })], []], seen);
  try {
    const settled = await hooks.toolBefore(facts(initialDate), { contracts: { arguments: dates } });
    assert.equal(settled.errors.length, 1);
    assert.equal(settled.input.toISOString(), initialDate.toISOString());
    assert.deepEqual(seen[1].params.event.tool.input, { at: initialDate.toISOString() });
  } finally { await hooks.close(); }
});
