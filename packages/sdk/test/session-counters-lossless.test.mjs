import test from "node:test";
import assert from "node:assert/strict";
import { parseInterceptRequest, parseInterceptResponse, validateInterceptRequest, validateInterceptResponse } from "../dist/src/draft/index.js";
import { parseJson, stringifyJson, addCanonicalSchemas } from "../dist/src/json.js";
import { assertJsonValue } from "../dist/src/validation.js";
import { BackendTransport } from "../dist/src/client/transport.js";
import { Ajv2020 } from "ajv/dist/2020.js";

const huge = 900719925474099312345678901234567890n;
function request(counters = {}) {
  return {
    jsonrpc: "2.0", id: "event", method: "hooks/intercept",
    params: {
      protocolVersion: "draft", capabilities: { effects: [] },
      event: {
        id: "event", type: "tool.before", source: "urn:test:lossless",
        time: "2026-01-01T00:00:00Z", path: "native", call: { id: "call" },
        tool: { name: "read", origin: "native", input: { opaque: -huge } },
        session: { id: "session", counters, unknown: { exact: huge } },
      },
    },
  };
}

test("session counters decode completely, preserving optional fields and integer extras", () => {
  const counters = { turns: 0, modelRequests: huge, inputTokens: huge + 1n, outputTokens: 1, toolCalls: 2n, futureCounter: huge + 2n };
  const value = request(counters);
  const result = parseInterceptRequest(stringifyJson(value));
  assert.equal(result.ok, true, JSON.stringify(result.errors));
  assert.equal(result.value.params.event.session.counters.modelRequests, huge);
  assert.equal(result.value.params.event.session.counters.futureCounter, huge + 2n);
  assert.equal(result.value.params.event.session.unknown.exact, huge);
  assert.equal(result.value.params.event.tool.input.opaque, -huge);
  assert.deepEqual(Object.keys(validateInterceptRequest(request()).value.params.event.session.counters), []);
  assert.equal(value.params.event.session.counters, counters);
});

test("canonical counter validation rejects negative, fractional and noninteger extras without mutation", () => {
  for (const counter of [-1, -huge, 1.5, "1", null]) {
    for (const key of ["turns", "futureCounter"]) {
      const value = request({ [key]: counter });
      assert.equal(validateInterceptRequest(value).ok, false);
      assert.equal(value.params.event.session.counters[key], counter);
    }
  }
  const withoutCounters = request();
  delete withoutCounters.params.event.session.counters;
  assert.equal(validateInterceptRequest(withoutCounters).ok, true);
});

test("canonical numeric type unions, exact bounds and unrelated constraints remain enforced", () => {
  const registry = new Ajv2020({ strict: false, allErrors: true });
  addCanonicalSchemas(registry);
  // Numeric constraints are present in canonical counter schemas; extension JSON
  // remains opaque and may contain arbitrary signed integer values.
  const counters = registry.getSchema("https://agenthooksprotocol.org/schemas/draft/common.schema.json#/$defs/SessionCounters");
  assert.equal(counters({ future: huge }), true);
  assert.equal(counters({ future: -huge }), false);
  assert.equal(counters({ future: true }), false);
  const malformed = request({ turns: huge });
  malformed.params.event.time = "not-a-time";
  assert.equal(validateInterceptRequest(malformed).ok, false);
  assert.doesNotThrow(() => assertJsonValue({ extension: -huge }));
});

test("absent effects decode as neutral without mutating wire, while null remains invalid", () => {
  const response = { jsonrpc: "2.0", id: "event", result: { protocolVersion: "draft", extra: huge } };
  const result = validateInterceptResponse(response);
  assert.equal(result.ok, true);
  assert.deepEqual(result.value.result.effects ?? [], []);
  assert.equal(Object.hasOwn(response.result, "effects"), false);
  assert.equal(parseInterceptResponse(stringifyJson(response)).value.result.extra, huge);
  assert.equal(validateInterceptResponse({ ...response, result: { ...response.result, effects: null } }).ok, false);
});

test("HTTP request and response round-trip exact integers and preserve envelope checks", async () => {
  let seen;
  const transport = new BackendTransport({ transport: { type: "http", url: "https://backend.test/hooks" } }, async (_url, init) => {
    seen = parseJson(init.body);
    return new Response(stringifyJson({ jsonrpc: "2.0", id: seen.id, result: { protocolVersion: "draft", exact: huge, unknown: { signed: -huge } } }), { headers: { "content-type": "application/json" } });
  });
  try {
    const response = await transport.request(request({ turns: huge, futureCounter: huge + 1n }));
    assert.equal(seen.params.event.session.counters.turns, huge);
    assert.equal(seen.params.event.session.counters.futureCounter, huge + 1n);
    assert.equal(response.result.exact, huge);
    assert.equal(response.result.unknown.signed, -huge);
  } finally { await transport.close(); }
  for (const [body, code] of [
    ["{", "MALFORMED_JSON"],
    ['{"jsonrpc":"2.0","id":"other","result":{}}', "ID_MISMATCH"],
    ['{"jsonrpc":"2.0","id":"event","result":{},"error":{}}', "MALFORMED_JSON_RPC"],
  ]) {
    const invalid = new BackendTransport({ transport: { type: "http", url: "https://backend.test/hooks" } }, async () => new Response(body, { headers: { "content-type": "application/json" } }));
    try { await assert.rejects(invalid.request(request()), { code }); }
    finally { await invalid.close(); }
  }
});

test("lossless JSON helpers reject malformed syntax and trailing JSON", () => {
  for (const text of ["1,2", '1,"injected":true', "{", "[1,]", "01", "true false"]) {
    assert.throws(() => parseJson(text), SyntaxError);
  }
  assert.equal(parseJson(stringifyJson({ exact: huge })).exact, huge);
});
import { Hooks } from 'agenthooksprotocol/client';

test('public Hooks preserves exact session counters and opaque tool integers through admission and settlement', async () => {
  const counters = { turns: huge, modelRequests: huge + 1n, toolCalls: 2, inputTokens: huge + 2n, outputTokens: 0, future: huge + 3n };
  let requestText;
  const hooks = new Hooks({ protocolVersion: 'draft', hooks: [{ id: 'test.exact.public', transport: { type: 'http', url: 'https://backend.test/hooks' }, subscriptions: [{ mode: 'intercept', events: ['tool.before'], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'metadata' } }] }] }, {
    source: 'urn:test:exact:public', capabilities: { 'tool.before': { effects: ['return'] } }, fetch: async (_, init) => {
      requestText = init.body;
      const request = parseJson(requestText);
      assert.equal(request.params.event.session.counters.turns, huge);
      assert.equal(request.params.event.tool.input.opaque, -huge);
      return new Response(stringifyJson({ jsonrpc: '2.0', id: request.id, result: { protocolVersion: 'draft', effects: [{ type: 'return', value: huge + 4n }], future: { exact: huge } } }), { headers: { 'content-type': 'application/json' } });
    },
  });
  try {
    const bigintResult = { decode(value) { assert.equal(typeof value, 'bigint'); return value; }, encode(value) { return value; } };
    const settled = await hooks.toolBefore({ callId: 'call', name: 'read', input: { opaque: -huge }, origin: 'native', path: 'native', session: { id: 'session', counters } }, { contracts: { result: bigintResult } });
    assert.deepEqual(settled.errors, []);
    assert.deepEqual(settled.event.session.counters, counters);
    assert.equal(settled.input.opaque, -huge);
    assert.equal(settled.state.candidate.value, huge + 4n);
    assert.equal(requestText.includes(`"turns":${huge}`), true);
  } finally { await hooks.close(); }
});
