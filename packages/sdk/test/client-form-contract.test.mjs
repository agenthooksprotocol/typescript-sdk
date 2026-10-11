import test from 'node:test';
import assert from 'node:assert/strict';
import { Hooks, Type, form } from 'agenthooksprotocol/client';

const choice = () => Type.Union([Type.Literal('red'), Type.Literal('blue')]);
const schema = () => Type.Object({
  name: Type.String({ minLength: 2, maxLength: 8 }),
  email: Type.String({ format: 'email' }),
  age: Type.Integer({ minimum: 18, maximum: 100 }),
  ratio: Type.Number({ minimum: 0, maximum: 1 }),
  enabled: Type.Boolean(),
  color: choice(),
  colors: Type.Array(choice(), { minItems: 1, maxItems: 2 }),
  note: Type.Optional(Type.String()),
});
const answer = () => ({ name: 'Ada', email: 'ada@example.test', age: 37, ratio: 0.5, enabled: true, color: 'red', colors: ['blue'] });

test('one TypeBox declaration derives the generated MCP request and answer contract', () => {
  const declaration = schema();
  const snapshot = structuredClone(declaration);
  const f = form(declaration);
  assert.deepEqual(f.request('Tell us about yourself'), {
    mode: 'form', message: 'Tell us about yourself', requestedSchema: {
      type: 'object', required: ['name', 'email', 'age', 'ratio', 'enabled', 'color', 'colors'],
      properties: {
        name: { type: 'string', minLength: 2, maxLength: 8 },
        email: { type: 'string', format: 'email' },
        age: { type: 'integer', minimum: 18, maximum: 100 },
        ratio: { type: 'number', minimum: 0, maximum: 1 },
        enabled: { type: 'boolean' }, color: { type: 'string', enum: ['red', 'blue'] },
        colors: { type: 'array', items: { type: 'string', enum: ['red', 'blue'] }, minItems: 1, maxItems: 2 },
        note: { type: 'string' },
      },
    },
  });
  assert.deepEqual(structuredClone(declaration), snapshot);
  const wire = { action: 'accept', content: answer(), _meta: { correlation: 'id' }, future: { nested: [true] } };
  const wireSnapshot = structuredClone(wire);
  assert.deepEqual(f.decode(wire), wire);
  assert.deepEqual(f.codec.decode(wire), wire);
  assert.deepEqual(f.answer.decode(wire.content), wire.content);
  assert.deepEqual(wire, wireSnapshot);
});

test('answer validation never coerces, drops fields, inserts defaults or relaxes constraints', () => {
  const f = form(schema());
  for (const changes of [
    { name: 'A' }, { name: 'much-too-long' }, { email: 'invalid' }, { age: '37' },
    { age: 17 }, { age: 101 }, { age: 18.5 }, { ratio: -0.1 }, { ratio: 1.1 },
    { enabled: 'true' }, { color: 'green' }, { colors: [] },
    { colors: ['red', 'blue', 'red'] }, { colors: ['green'] }, { colors: [1] },
  ]) {
    const wire = { action: 'accept', content: { ...answer(), ...changes } };
    const snapshot = structuredClone(wire);
    assert.throws(() => f.decode(wire));
    assert.deepEqual(wire, snapshot);
  }
  const missing = answer();
  delete missing.name;
  assert.throws(() => f.decode({ action: 'accept', content: missing }));
  const defaultForm = form(Type.Object({ name: Type.String({ default: 'Ada' }) }));
  assert.throws(() => defaultForm.decode({ action: 'accept', content: {} }));
  // Plain Type.Object is open: unknown primitive answers survive unchanged.
  const wire = { action: 'accept', content: { ...answer(), extra: 'preserve' } };
  assert.deepEqual(f.decode(wire), wire);
  // MCP itself excludes nested answer values, even for unknown fields.
  assert.throws(() => f.decode({ action: 'accept', content: { ...answer(), extra: {} } }));
});

test('canonical result actions include decline, cancel and content-free URL acceptance', () => {
  const f = form(schema());
  for (const action of ['decline', 'cancel']) {
    assert.deepEqual(f.decode({ action, _meta: { trace: 1 } }), { action, _meta: { trace: 1 } });
  }
  const url = { action: 'accept', _meta: { trace: 1 } };
  assert.deepEqual(f.decode(url, 'url'), url);
  assert.throws(() => f.decode(url));
  assert.throws(() => f.codec.decode(url));
  for (const action of ['accept', 'decline', 'cancel']) {
    assert.throws(() => f.decode({ action, content: answer() }, 'url'));
  }
  const optional = form(Type.Object({ note: Type.Optional(Type.String()) }));
  assert.deepEqual(optional.decode({ action: 'accept' }), { action: 'accept' });
  assert.equal(Object.hasOwn(optional.decode({ action: 'accept' }), 'content'), false);
  for (const wire of [null, {}, { action: 'unknown' }, { action: 'accept', content: null },
    { action: 'decline', content: answer() }, { action: 'cancel', content: answer() },
    { action: 'accept', content: answer(), _meta: [] }]) assert.throws(() => f.decode(wire));
});

for (const [format, valid, invalid] of [
  ['date', '2024-02-29', '2023-02-29'],
  ['date-time', '2024-02-29T10:00:00Z', 'yesterday'],
  ['email', 'ada@example.test', 'not-an-email'],
  ['uri', 'https://example.test/path', 'not a URI'],
]) test(`supported ${format} format is advertised and validated`, () => {
  const f = form(Type.Object({ value: Type.String({ format }) }));
  assert.equal(f.requestedSchema.properties.value.format, format);
  assert.deepEqual(f.decode({ action: 'accept', content: { value: valid } }).content, { value: valid });
  assert.throws(() => f.decode({ action: 'accept', content: { value: invalid } }));
});

test('unsupported form shapes and keywords fail at construction instead of approximating', () => {
  for (const field of [
    Type.Object({ nested: Type.String() }), Type.Array(Type.String()), Type.Array(Type.Number()),
    Type.Tuple([Type.String()]), Type.Null(), Type.Any(), Type.Unknown(),
    Type.Union([Type.String(), Type.Number()]), Type.Union([Type.Literal(1), Type.Literal(2)]),
    Type.String({ pattern: '^a' }), Type.String({ format: 'uuid' }),
    Type.Number({ exclusiveMinimum: 0 }), Type.Number({ multipleOf: 2 }),
    Type.Array(choice(), { uniqueItems: true }), Type.String({ customKeyword: true }),
    Type.Union([Type.Literal('a', { title: 'A' }), Type.Literal('b')]),
  ]) assert.throws(() => form(Type.Object({ value: field })), /Unsupported|Expected/);
  for (const root of [
    Type.Object({ value: Type.String() }, { additionalProperties: false }),
    Type.Object({ value: Type.String() }, { minProperties: 1 }),
    Type.Object({ value: Type.String() }, { title: 'Unsupported root annotation' }),
    Type.Array(Type.String()),
  ]) assert.throws(() => form(root), /Unsupported|requires/);
  for (const field of [Type.String({ minLength: -1 }), Type.Array(choice(), { maxItems: -1 })]) {
    assert.throws(() => form(Type.Object({ value: field })));
  }
});

test('string literal singletons and field annotations survive lowering', () => {
  const f = form(Type.Object({ value: Type.Literal('fixed', { title: 'Label', description: 'Help', default: 'fixed' }) }));
  assert.deepEqual(f.requestedSchema.properties.value, {
    type: 'string', enum: ['fixed'], title: 'Label', description: 'Help', default: 'fixed',
  });
  assert.deepEqual(f.decode({ action: 'accept', content: { value: 'fixed' } }).content, { value: 'fixed' });
  assert.throws(() => f.decode({ action: 'accept', content: { value: 'other' } }));
});

function formHooks(replies, seen) {
  const type = 'user.elicitation.request';
  return new Hooks({ protocolVersion: 'draft', hooks: replies.map((_, index) => ({
    id: `test.form.backend${index}`, transport: { type: 'http', url: `https://backend${index}.test/hooks` },
    subscriptions: [{ mode: 'intercept', events: [type], timeoutMs: 1000, failurePolicy: 'fail-open', content: { default: 'body' } }],
  })) }, {
    source: 'urn:test:forms', capabilities: { [type]: { effects: ['return'], elicitation: { form: {} } } },
    fetch: async (url, init) => {
      const wire = JSON.parse(init.body);
      seen.push(wire);
      const index = Number(String(url).match(/backend(\d+)/)[1]);
      return Response.json({ jsonrpc: '2.0', id: wire.id, result: { protocolVersion: 'draft', effects: replies[index] } });
    },
  });
}
function formFacts(f) {
  return { elicitation: { mode: 'form', server: 'test', request: {
    id: 'request', kind: 'text', mediaType: 'text/plain', selection: 'body', text: JSON.stringify(f.request('Answer?')),
  } } };
}
const returned = value => ({ type: 'return', value });

test('Hooks form requests serialize as generated inline text and admit typed form results', async () => {
  const f = form(schema());
  const value = { action: 'accept', content: answer() };
  const seen = [];
  const hooks = formHooks([[returned(value)]], seen);
  try {
    const settled = await hooks.userElicitationRequest(formFacts(f), { contracts: { result: f.codec } });
    assert.deepEqual(settled.errors, []);
    assert.deepEqual(settled.state.candidate.value, value);
    assert.deepEqual(JSON.parse(seen[0].params.event.elicitation.request.text), f.request('Answer?'));
    assert.deepEqual(settled.event.elicitation.request.text, JSON.stringify(f.request('Answer?')));
  } finally { await hooks.close(); }
});

for (const [label, invalid] of [
  ['missing content', { action: 'accept' }],
  ['missing required field', { action: 'accept', content: { lower: 1 } }],
  ['invariant violation', { action: 'accept', content: { lower: 8, upper: 2 } }],
  ['coercible field', { action: 'accept', content: { lower: '1', upper: 2 } }],
  ['decline content', { action: 'decline', content: { lower: 1, upper: 2 } }],
  ['cancel content', { action: 'cancel', content: { lower: 1, upper: 2 } }],
]) test(`Hooks rolls back ${label}; later receivers retain the prior accepted form answer`, async () => {
  const f = form(Type.Object({ lower: Type.Number(), upper: Type.Number() }), value => {
    if (value.lower > value.upper) throw Error('lower exceeds upper');
  });
  const accepted = { action: 'accept', content: { lower: 1, upper: 2 } };
  const seen = [];
  const hooks = formHooks([[returned(accepted)], [returned(invalid)], []], seen);
  try {
    const settled = await hooks.userElicitationRequest(formFacts(f), { contracts: { result: f.codec } });
    assert.equal(settled.errors.length, 1);
    assert.equal(seen.length, 3);
    assert.deepEqual(settled.state.candidate.value, accepted);
    assert.deepEqual(seen[2].params.state.candidate.value, accepted);
    assert.deepEqual(JSON.parse(seen[2].params.event.elicitation.request.text), f.request('Answer?'));
  } finally { await hooks.close(); }
});

test('form advertisement is immutable without freezing the caller declaration', () => {
  const declaration = Type.Object({ colors: Type.Array(choice(), { default: ['red'] }) });
  const before = JSON.stringify(declaration);
  const f = form(declaration);
  assert.equal(JSON.stringify(declaration), before);
  assert.equal(Object.isFrozen(declaration.properties.colors.default), false);
  assert.equal(Object.isFrozen(f.requestedSchema.properties.colors.default), true);
  assert.throws(() => { f.requestedSchema.properties.colors.default.push('blue'); });
  assert.throws(() => f.request(123));
});
