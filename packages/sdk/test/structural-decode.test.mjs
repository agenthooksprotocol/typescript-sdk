import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { draftCodecs, effectNames, supports } from 'agenthooksprotocol/draft';
import { supports as clientSupports } from 'agenthooksprotocol/client';
import { supports as serverSupports } from 'agenthooksprotocol/server';

test('effect-family queries are exported and do not infer grants', () => {
  for (const query of [supports, clientSupports, serverSupports]) {
    assert.equal(query({effects:['deny']}, effectNames.deny), true);
    assert.equal(query({effects:['vendor.custom']}, 'vendor.custom'), true);
    assert.equal(query({effects:[],modify:{input:{replace:true}}}, effectNames.modify), false);
  }
});

// Bundled generator-owned acceptance matrix also runs in standalone SDK CI.
const matrixPath = process.env.AHP_STRUCTURAL_MATRIX ?? new URL('./fixtures/structural-acceptance.json', import.meta.url);
test('exported runtime parsers agree for object and JSON input', () => {
  for (const entry of JSON.parse(readFileSync(matrixPath, 'utf8')).cases) {
    const name = entry.root.split('_').map(s => s[0].toUpperCase() + s.slice(1)).join('');
    for (const input of [entry.value, JSON.stringify(entry.value)]) {
      const parsed = draftCodecs[`parse${name}`](input);
      assert.equal(parsed.ok, entry.accepted, entry.id);
      assert.equal(parsed.diagnostics.some(d => d.severity === 'warning'), entry.warning, entry.id);
      assert.deepEqual(JSON.parse(JSON.stringify(parsed.raw)), entry.value, entry.id);
      if (parsed.ok) assert.deepEqual(JSON.parse(draftCodecs[`encode${name}`](parsed.value)), entry.value, entry.id);
    }
  }
});

test('runtime decode preserves candidate presence and forward compatibility', () => {
  const request = {
    jsonrpc: '2.0', id: 0, method: 'hooks/intercept',
    params: {
      protocolVersion: 'draft', event: {type: 'vendor.future', future: {nested: 1}},
      capabilities: {effects: ['deny', 'vendor.custom']},
      state: {permission: 'none', candidate: null},
    },
  };
  for (const candidate of [null, {value:null}, {value:0}, {value:false}]) {
    const input = structuredClone(request);
    input.params.state.candidate = candidate;
    const parsed = draftCodecs.parseInterceptRequest(input);
    assert.equal(parsed.ok, true);
    assert.deepEqual(JSON.parse(draftCodecs.encodeInterceptRequest(parsed.value)), input);
    assert.equal(parsed.diagnostics.some(d => d.code === 'unknown_variant'), true);
    assert.equal(supports(parsed.value.params.capabilities, effectNames.deny), true);
    assert.equal(supports(parsed.value.params.capabilities, 'vendor.custom'), true);
  }
  for (const mutate of [
    r => {delete r.params.state.candidate;},
    r => {r.params.state.candidate = {};},
    r => {r.jsonrpc = '1.0';},
    r => {r.params.event = {type:'tool.before'};},
  ]) {
    const input = structuredClone(request);
    mutate(input);
    assert.equal(draftCodecs.parseInterceptRequest(input).ok, false);
  }
});

test('object-input decoding accepts JSON data, not arbitrary JavaScript objects', () => {
  const reference = {ref: 'opaque-reference'};
  class RecordLike { field = 1; }
  let getterCalls = 0;
  const accessor = Object.defineProperty({}, 'field', {
    enumerable: true,
    get() { getterCalls++; return 1; },
  });
  const arrayAccessor = Object.defineProperty([0], '0', {
    enumerable: true,
    get() { getterCalls++; return 1; },
  });
  const symbol = {[Symbol('extension')]: 1};
  const hidden = Object.defineProperty({}, 'hidden', {value: 1});
  const cyclic = {}; cyclic.self = cyclic;
  for (const extension of [new RecordLike(), new Date(), new Map(), accessor,
    arrayAccessor, symbol, hidden, cyclic, Array(1), undefined, NaN, Infinity]) {
    const parsed = draftCodecs.parseContentReference({...reference, extension});
    assert.equal(parsed.ok, false);
    assert.equal(parsed.diagnostics[0].code, 'invalid_json');
  }
  assert.equal(getterCalls, 0, 'decoding must not execute accessors');
  const shared = Object.assign(Object.create(null), {nested: 1});
  const parsed = draftCodecs.parseContentReference({...reference, extension: [shared, shared]});
  assert.equal(parsed.ok, true, JSON.stringify(parsed.diagnostics));
  assert.deepEqual(JSON.parse(draftCodecs.encodeContentReference(parsed.value)), {
    ...reference, extension: [{nested: 1}, {nested: 1}],
  });
});
