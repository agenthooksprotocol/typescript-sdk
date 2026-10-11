import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as draft from 'agenthooksprotocol/draft';
import * as generated from 'agenthooksprotocol/generated';

const require = createRequire(import.meta.url);

test('draft facade and codec namespace expose public helpers, not runtime-private projection', () => {
  for (const name of ['parseInterceptRequest', 'parseInterceptResponse', 'parseContentReference', 'encodeContentReference', 'responseForRequest', 'toEventInput']) {
    assert.equal(typeof draft.draftCodecs[name], 'function', name);
  }
  for (const name of ['PendingAttachment', 'HostInputProjection', '_projectHostInput']) {
    assert.equal(name in generated, false, `generated.${name}`);
    assert.equal(name in draft, false, name);
    assert.equal(name in draft.draftCodecs, false, `draftCodecs.${name}`);
  }
});

test('generated package facade decodes omitted effects as a no-op and rejects arbitrary JSON effects', () => {
  const response = { jsonrpc: '2.0', id: 'no-effect', result: { protocolVersion: 'draft' } };
  for (const parser of [generated.parseInterceptNoEffectResponse, generated.parseInterceptResponse]) {
    for (const input of [response, JSON.stringify(response)]) {
      const parsed = parser(input);
      assert.equal(parsed.ok, true);
      assert.deepEqual(parsed.value.result.effects ?? [], []);
      assert.equal('effects' in parsed.raw.result, false, 'decoding must preserve omitted wire fields');
    }
    for (const effects of [[null], [1], ['allow'], [{}], [{ type: 'deny', unexpected: true }]]) {
      assert.equal(parser({ ...response, result: { ...response.result, effects } }).ok, false);
    }
    assert.equal(parser({ ...response, result: { ...response.result, effects: [{ type: 'allow' }] } }).ok, true);
  }
});

test('raw and obsolete generated draft runtimes are not public package subpaths', () => {
  for (const path of ['draft/raw', 'draft/generated', 'dist/src/draft/raw.js']) {
    assert.throws(() => require.resolve(`agenthooksprotocol/${path}`), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
  }
});
