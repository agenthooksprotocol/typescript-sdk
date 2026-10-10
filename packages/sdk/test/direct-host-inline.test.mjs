import test from 'node:test';
import assert from 'node:assert/strict';
import { Hooks, Attachment } from 'agenthooksprotocol/client';

const facts = { turn: { id: 'turn' }, trigger: 'user' };
const attachmentPart = body => ({ kind: 'attachment', mediaType: 'application/octet-stream', body });
function hooks(selection, fetch, backends = 1) {
  const subscriptions = [{ mode: 'intercept', events: ['turn.start'], timeoutMs: 1000, failurePolicy: 'fail-closed', content: { default: selection } }];
  return new Hooks({ protocolVersion: 'draft', hooks: Array.from({ length: backends }, (_, i) => ({
    id: `test.inline.backend${i}`, transport: { type: 'http', url: `https://backend${i}.test/hooks` },
    subscriptions: subscriptions.map(s => ({ ...s, ...(selection === 'body' ? { upload: { endpoint: `https://backend${i}.test/upload`, maxBytes: 1024, timeoutMs: 1000 } } : {}) })),
  })) }, { source: 'urn:test:inline', capabilities: { 'turn.start': { effects: [] } }, fetch });
}
const accept = wire => Response.json({ jsonrpc: '2.0', id: wire.id, result: { protocolVersion: 'draft', effects: [] } });

test('normal Hooks method accepts direct ordered inline messages and uploads the exact owner once per selected backend', async () => {
  let opens = 0, disposes = 0;
  const owner = Attachment.lazy(() => { opens++; return new Uint8Array([1, 2, 3]); }, () => { disposes++; });
  const events = [], uploads = [];
  const client = hooks('body', async (url, init) => {
    if (String(url).endsWith('/upload')) {
      uploads.push(new Uint8Array(init.body));
      const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', init.body))].map(x => x.toString(16).padStart(2, '0')).join('');
      return Response.json({ ref: String(url), size: 3, sha256: hash }, { status: 201 });
    }
    const wire = JSON.parse(init.body); events.push(wire.params.event); return accept(wire);
  }, 2);
  const result = await client.turnStart({ ...facts, items: [{ role: 'user', parts: [{ kind: 'text', text: JSON.stringify({ question: 'read this' }) }, attachmentPart(owner)] }] });
  assert.deepEqual(result.errors, []);
  assert.equal(opens, 1);
  assert.equal(uploads.length, 2);
  for (const bytes of uploads) assert.deepEqual([...bytes], [1, 2, 3]);
  assert.equal(events.length, 2);
  for (const event of events) {
    assert.equal(event.items[0].role, 'user');
    assert.equal(event.items[0].parts[0].text, '{"question":"read this"}');
    assert.deepEqual(event.items[0].parts[1].body, { ref: event.items[0].parts[1].body.ref });
    assert.equal(event.items[0].parts[1].selection, 'body');
    assert.match(event.items[0].parts[1].body.ref, /^https:/);
  }
  assert.equal(result.event.items[0].parts[1].body, owner);
  await client.close();
  assert.deepEqual([...await result.content.read(result.event.items[0].parts[1].id)], [1, 2, 3]);
  await result.content.close();
  assert.equal(disposes, 1);
});

for (const selection of ['metadata', 'omit']) test(`${selection} selection strips inline text and never opens attachments`, async () => {
  let opens = 0, disposes = 0, event;
  const owner = Attachment.lazy(() => { opens++; throw Error('read forbidden'); }, () => { disposes++; });
  const client = hooks(selection, async (_, init) => { const wire = JSON.parse(init.body); event = wire.params.event; return accept(wire); });
  const result = await client.turnStart({ ...facts, items: [{ role: 'user', parts: [{ kind: 'text', text: 'private' }, attachmentPart(owner)] }] });
  assert.deepEqual(result.errors, []);
  for (const part of event.items[0].parts) {
    assert.equal(part.selection, selection);
    assert.equal('text' in part, false); assert.equal('body' in part, false);
  }
  await client.close();
  assert.equal(opens, 0);
  assert.equal(disposes, 0);
  assert.equal(result.event.items[0].parts[1].body, owner);
  await result.content.close();
  assert.equal(disposes, 1);
});

test('invalid textual attachment closes without reading or delivering', async () => {
  let opens = 0, closes = 0, sends = 0;
  const owner = Attachment.lazy(() => { opens++; return new Uint8Array(); }, () => { closes++; });
  const client = hooks('body', async () => { sends++; throw Error('unexpected delivery'); });
  await assert.rejects(client.turnStart({ ...facts, items: [{ role: 'user', parts: [{ kind: 'attachment', mediaType: 'application/json', body: owner }] }] }), /text and JSON attachments/);
  assert.equal(opens, 0); assert.equal(closes, 1); assert.equal(sends, 0);
  await client.close();
});

test('native and provider payloads are never inspected for ownership', async () => {
  let examined = 0, disposed = 0;
  const opaque = {};
  Object.defineProperty(opaque, 'trap', { enumerable: true, get() { examined++; throw Error('opaque traversal'); } });
  const hidden = Attachment.lazy(() => { throw Error('unexpected read'); }, () => { disposed++; });
  const client = hooks('metadata', async (_, init) => accept(JSON.parse(init.body)));
  const result = await client.turnStart({ ...facts, native: { type: 'test', payload: opaque, hidden }, items: [{ role: 'user', parts: [{ kind: 'text', text: 'public' }] }] });
  assert.deepEqual(result.errors, []); assert.equal(examined, 0); assert.equal(disposed, 0);
  await client.close(); await hidden.close();
});


test('direct host message and attachment declarations type-check', async () => {
  const { spawnSync } = await import('node:child_process');
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const result = spawnSync(process.execPath, [require.resolve('typescript/bin/tsc'),
    '--noEmit', '--strict', '--exactOptionalPropertyTypes', '--target', 'ES2022',
    '--module', 'NodeNext', '--moduleResolution', 'NodeNext', '--lib', 'ES2022,DOM', '--skipLibCheck',
    'packages/sdk/test/direct-host-inline-types.ts', 'node-shims.d.ts'], { encoding: 'utf8', timeout: 30000 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});


test('schema traversal preserves absent optional content fields', async () => {
  let wire;
  const client = new Hooks({ protocolVersion: 'draft', hooks: [{
    id: 'test.optional', transport: { type: 'http', url: 'https://backend.test/hooks' },
    subscriptions: [{ mode: 'intercept', events: ['tool.before'], timeoutMs: 1000,
      failurePolicy: 'fail-closed', content: { default: 'metadata' } }],
  }] }, { source: 'urn:test:optional', capabilities: { 'tool.before': { effects: [] } },
    fetch: async (_, init) => { wire = JSON.parse(init.body); return accept(wire); } });
  const result = await client.toolBefore({ callId: 'call', name: 'read', input: {}, path: 'native', origin: 'native' });
  assert.deepEqual(result.errors, []);
  assert.equal(Object.hasOwn(result.event, 'items'), false);
  assert.equal(Object.hasOwn(wire.params.event, 'items'), false);
  await client.close();
});


test('pre-cancelled normal boundary closes direct attachments without opening', async () => {
  let opens = 0, closes = 0;
  const owner = Attachment.lazy(() => { opens++; return new Uint8Array([1]); }, () => { closes++; });
  const client = hooks('body', async () => { throw Error('unexpected delivery'); });
  const result = await client.turnStart({ ...facts, items: [{ role: 'user', parts: [attachmentPart(owner)] }] }, { signal: AbortSignal.abort() });
  assert.equal(result.interrupted, true);
  assert.equal(result.content, undefined);
  assert.equal(opens, 0); assert.equal(closes, 1);
  await client.close();
});

test('failed conversion cleans fresh sources but preserves earlier result-owned attachments', async () => {
  let opensA = 0, disposesA = 0, opensB = 0, disposesB = 0;
  const a = Attachment.lazy(() => { opensA++; return new Uint8Array([7, 8]); }, () => { disposesA++; });
  const b = Attachment.lazy(() => { opensB++; throw Error('Fresh rejected source must not open'); }, () => { disposesB++; });
  const client = hooks('metadata', async (_, init) => accept(JSON.parse(init.body)));
  let result;
  try {
    result = await client.turnStart({ ...facts, items: [{ role: 'user', parts: [{ ...attachmentPart(a), id: 'a' }] }] });
    assert.deepEqual(result.errors, []);
    assert.equal(result.event.items[0].parts[0].body, a);
    await assert.rejects(client.turnStart({ ...facts, items: [{ role: 'user', parts: [
      { ...attachmentPart(a), id: 'a' },
      { kind: 'text', text: 123 },
      { ...attachmentPart(b), id: 'b' },
      { ...attachmentPart(b), id: 'b-again' },
    ] }] }), /invalid inline text/);
    assert.equal(opensA, 0); assert.equal(disposesA, 0);
    assert.equal(opensB, 0); assert.equal(disposesB, 1);
    await client.close();
    assert.deepEqual([...await result.content.read('a')], [7, 8]);
    assert.deepEqual([...await result.content.read('a')], [7, 8]);
    assert.equal(opensA, 1); assert.equal(disposesA, 1);
    await result.content.close();
    await assert.rejects(a.read(), /Attachment closed/);
    assert.equal(disposesA, 1); assert.equal(disposesB, 1);
  } finally {
    await result?.content?.close();
    await client.close();
  }
});

test('failed conversion cannot interrupt an earlier in-flight attachment owner', async () => {
  let enter, release, sourceSignal;
  const entered = new Promise(resolve => { enter = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  let opensA = 0, disposesA = 0, opensB = 0, disposesB = 0, uploads = 0, deliveries = 0;
  const a = Attachment.lazy(async signal => {
    sourceSignal = signal; opensA++; enter(); await gate;
    signal.throwIfAborted(); return new Uint8Array([9]);
  }, () => { disposesA++; });
  const b = Attachment.lazy(() => { opensB++; throw Error('Fresh rejected source must not open'); }, () => { disposesB++; });
  const client = hooks('body', async (url, init) => {
    if (String(url).endsWith('/upload')) {
      uploads++;
      const sha256 = [...new Uint8Array(await crypto.subtle.digest('SHA-256', init.body))].map(x => x.toString(16).padStart(2, '0')).join('');
      return Response.json({ ref: 'stored', size: 1, sha256 }, { status: 201 });
    }
    deliveries++; return accept(JSON.parse(init.body));
  });
  const pending = client.turnStart({ ...facts, items: [{ role: 'user', parts: [{ ...attachmentPart(a), id: 'a' }] }] });
  let result;
  try {
    await entered;
    await assert.rejects(client.turnStart({ ...facts, items: [{ role: 'user', parts: [
      { ...attachmentPart(a), id: 'a' }, { ...attachmentPart(b), id: 'b' }, { kind: 'text', text: 123 },
    ] }] }), /invalid inline text/);
    assert.equal(sourceSignal.aborted, false);
    assert.equal(disposesA, 0);
    assert.equal(opensB, 0); assert.equal(disposesB, 1);
    release();
    result = await pending;
    assert.deepEqual(result.errors, []); assert.equal(result.interrupted, false);
    assert.equal(uploads, 1); assert.equal(deliveries, 1); assert.equal(opensA, 1);
    await client.close();
    assert.deepEqual([...await result.content.read('a')], [9]);
    await result.content.close();
    await assert.rejects(a.read(), /Attachment closed/);
    assert.equal(disposesA, 1); assert.equal(disposesB, 1);
  } finally {
    release();
    await pending.then(value => value.content?.close(), () => {});
    await result?.content?.close();
    await client.close();
  }
});
