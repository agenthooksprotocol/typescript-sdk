import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Attachment, Hooks, contentSlots } from 'agenthooksprotocol/client';

const type = 'context.compact.before';
const item = (body) => ({ id: 'instructions', kind: 'text', mediaType: 'text/plain', body });
const input = (body) => ({ trigger: "manual", items: [], session: { id: 'session' }, instructions: item(body) });
function client(mode, extra = {}) {
  return new Hooks({ protocolVersion: 'draft', hooks: [1, 2].map(n => ({
    id: `example.consumer${n}`, transport: { type: 'http', url: 'https://example.test/hooks' },
    subscriptions: [{ mode: 'intercept', events: [mode ? type : "tool.before"], timeoutMs: 2000,
      failurePolicy: 'fail-closed', content: { default: mode ?? "metadata" },
      upload: { endpoint: 'https://example.test/upload', maxBytes: 100, timeoutMs: 100 } }],
  })) }, { source: 'urn:example:attachments', capabilities: {
    "tool.before": { modes: ["intercept"], capabilities: { effects: [] } },
    [type]: { modes: ['intercept'], capabilities: { effects: [] } },
  }, fetch: async (_, init) => Response.json({ jsonrpc: '2.0', id: JSON.parse(init.body).id,
    result: { protocolVersion: 'draft', effects: [] } }), ...extra });
}
for (const mode of [undefined, 'metadata', 'omit']) {
  test(`${mode ?? 'no match'} retains unopened source after shutdown`, async () => {
    let opens = 0, closes = 0;
    const attachment = Attachment.lazy(() => { opens++; return new Uint8Array([1, 2]); }, async () => { await Promise.resolve(); closes++; });
    const hooks = client(mode);
    const result = await hooks.dispatch(type, input(attachment));
    assert.equal(opens, 0);
    assert.equal(closes, 0);
    await hooks.close();
    const [a, b] = await Promise.all([result.content.read('instructions'), result.content.read('instructions')]);
    assert.deepEqual(a, new Uint8Array([1, 2]));
    a.fill(0);
    assert.deepEqual(b, new Uint8Array([1, 2]));
    assert.equal(opens, 1);
    await result.content.close();
    assert.equal(closes, 1);
    await assert.rejects(result.content.read('instructions'));
  });
}
test('eager bytes snapshot caller buffers and fan out independent uploads', async () => {
  const buffer = Buffer.from('hello');
  const attachment = Attachment.bytes(buffer);
  buffer.fill(0);
  let uploads = 0;
  const hooks = client('body', { fetch: async (url, init) => {
    if (String(url).endsWith('/upload')) {
      uploads++;
      assert.equal(new TextDecoder().decode(init.body), 'hello');
      const sha256 = createHash('sha256').update(init.body).digest('hex');
      init.body.fill(0);
      return Response.json({ ref: `ref-${uploads}`, size: 5, sha256 }, { status: 201 });
    }
    return Response.json({ jsonrpc: '2.0', id: JSON.parse(init.body).id, result: { protocolVersion: 'draft', effects: [] } });
  } });
  const result = await hooks.dispatch(type, input(attachment));
  assert.deepEqual(result.errors, []);
  assert.equal(uploads, 2);
  await hooks.close();
  assert.equal(new TextDecoder().decode(await result.content.read('instructions')), 'hello');
  await result.content.close();
  const other = client();
  await assert.rejects(other.dispatch(type, input(attachment)), /another invocation/);
  await other.close();
});
test('unopened disposal is awaited and idempotent', async () => {
  let closes = 0;
  const hooks = client();
  const result = await hooks.dispatch(type, input(Attachment.lazy(() => { throw Error('must not open'); }, async () => {
    await new Promise(r => setTimeout(r, 5)); closes++;
  })));
  await result.content.close();
  await result.content.close();
  assert.equal(closes, 1);
  await hooks.close();
});
test('result reads retain configured bounds and cache source failures', async () => {
  let opens = 0, closes = 0;
  const hooks = client(undefined, { maxContentBytes: 1 });
  const result = await hooks.dispatch(type, input(Attachment.lazy(() => { opens++; return new Uint8Array(2); }, () => { closes++; })));
  await hooks.close();
  for (let i = 0; i < 2; i++) await assert.rejects(result.content.read('instructions'), /limit/);
  assert.equal(opens, 1);
  await result.content.close();
  assert.equal(closes, 1);
});
test('pre-cancelled invocation disposes without opening', async () => {
  let closes = 0;
  const hooks = client();
  const result = await hooks.dispatch(type, input(Attachment.lazy(() => { throw Error('unexpected read'); }, () => { closes++; })), { signal: AbortSignal.abort() });
  assert.equal(result.interrupted, true);
  assert.equal(closes, 1);
  await hooks.close();
});
test('typed source binding preserves owned attachment identity', async () => {
  const hooks = client();
  const attachment = Attachment.bytes(new Uint8Array([9]));
  const { body, ...metadata } = item(attachment);
  const result = await hooks.contextCompactBefore({ trigger: 'manual', items: [], instructions: metadata }, {
    contentSources: [contentSlots[type].instructions(attachment)],
  });
  await hooks.close();
  assert.deepEqual(await result.content.read('instructions'), new Uint8Array([9]));
  await result.content.close();
});
for (const mode of ['timeout', 'read-error', 'invalid']) {
  test(`${mode} releases attachment source exactly once`, async () => {
    let opens = 0, closes = 0;
    const attachment = Attachment.lazy(signal => {
      opens++;
      if (mode === 'read-error') throw Error('unavailable');
      return new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
    }, () => { closes++; });
    const hooks = client('body');
    try {
      if (mode === 'invalid') {
        await assert.rejects(hooks.dispatch(type, { ...input(attachment), trigger: null }));
        assert.equal(opens, 0);
      } else {
        const result = await hooks.dispatch(type, input(attachment));
        assert.ok(result.errors.length > 0);
        await result.content?.close();
        assert.equal(opens, 1);
      }
      assert.equal(closes, 1);
    } finally { await hooks.close(); }
  });
}
test('conflicting ownership still disposes fresh later sources', async () => {
  const hooks = client();
  const reused = Attachment.bytes(new Uint8Array([1]));
  const result = await hooks.dispatch(type, input(reused));
  let closes = 0;
  await assert.rejects(hooks.dispatch(type, { ...input(reused), native: {
    later: Attachment.lazy(() => { throw Error('unexpected'); }, () => { closes++; }),
  } }), /another invocation/);
  assert.equal(closes, 1);
  assert.deepEqual(await result.content.read('instructions'), new Uint8Array([1]));
  await result.content.close();
  await hooks.close();
});
test('throwing disposer cannot retain invocation bookkeeping', async () => {
  const hooks = client();
  await assert.rejects(hooks.dispatch(type, input(Attachment.lazy(() => new Uint8Array(), () => { throw Error('dispose failed'); })), { signal: AbortSignal.abort() }), /dispose failed/);
  assert.equal(hooks.managers.size, 0);
  assert.equal(hooks.pending.size, 0);
  await hooks.close();
});
test('result accessor reflects accepted text edits without mutating original input', async () => {
  const original = input(Attachment.bytes(new TextEncoder().encode('original')));
  const hooks = client('metadata', {
    capabilities: { [type]: { effects: ['modify'], modify: { instructions: { replace: true, merge: false } } } },
    fetch: async (_, init) => Response.json({ jsonrpc: '2.0', id: JSON.parse(init.body).id,
      result: { protocolVersion: 'draft', effects: [{ type: 'modify', target: 'instructions', operation: 'replace', value: 'replacement' }] } }),
  });
  const result = await hooks.dispatch(type, original);
  assert.deepEqual(result.errors, []);
  assert.ok(original.instructions.body instanceof Attachment);
  await hooks.close();
  assert.equal(new TextDecoder().decode(await result.content.read('instructions')), 'replacement');
  await result.content.close();
});
test('closing a result cancels an in-flight lazy read', async () => {
  let started;
  const ready = new Promise(resolve => { started = resolve; });
  let aborted = false, closes = 0;
  const hooks = client();
  const result = await hooks.dispatch(type, input(Attachment.lazy(signal => {
    started();
    return new Promise((_, reject) => signal.addEventListener('abort', () => {
      aborted = true; reject(signal.reason);
    }, { once: true }));
  }, () => { closes++; })));
  await hooks.close();
  const read = result.content.read('instructions');
  const rejected = assert.rejects(read, /closed/);
  await ready;
  await result.content.close();
  await rejected;
  assert.equal(aborted, true);
  assert.equal(closes, 1);
});
for (const mode of [undefined, 'metadata']) {
  for (const field of ['size', 'sha256']) {
    test(`${mode ?? 'no match'} validates ${field} on fresh and cached result reads`, async () => {
      let opens = 0;
      const bytes = new Uint8Array([1, 2]);
      const event = input(Attachment.lazy(() => { opens++; return bytes; }));
      const valid = { size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') };
      Object.assign(event.instructions, valid, { [field]: field === 'size' ? 99 : '0'.repeat(64) });
      const hooks = client(mode);
      const result = await hooks.dispatch(type, event);
      await hooks.close();
      assert.equal(opens, 0);
      // Neither producer mutations nor compatibility event mutations can relax validation.
      Object.assign(event.instructions, valid);
      Object.assign(result.event.instructions, valid);
      try {
        for (let i = 0; i < 2; i++) {
          await assert.rejects(result.content.read('instructions'), field === 'size' ? /Content size mismatch/ : /Content SHA-256 mismatch/);
        }
        assert.equal(opens, 1);
      } finally { await result.content.close(); }
    });
  }
}
test('matching result metadata allows repeated independent reads after shutdown', async () => {
  const bytes = new Uint8Array([1, 2]);
  const event = input(Attachment.bytes(bytes));
  Object.assign(event.instructions, { size: 2, sha256: createHash('sha256').update(bytes).digest('hex') });
  const hooks = client('metadata');
  const result = await hooks.dispatch(type, event);
  await hooks.close();
  try {
    const first = await result.content.read('instructions');
    first.fill(0);
    assert.deepEqual(await result.content.read('instructions'), bytes);
  } finally { await result.content.close(); }
});
