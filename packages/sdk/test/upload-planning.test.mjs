import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Hooks, Attachment } from 'agenthooksprotocol/client';

const part = body => ({ kind: 'attachment', mediaType: 'application/octet-stream', body });
const input = (...owners) => ({ turn: { id: 'turn' }, trigger: 'user', items: [{ role: 'user', parts: owners.map(part) }] });
const subscription = (overrides = {}) => ({ mode: 'intercept', events: ['turn.start'], timeoutMs: 1000,
  failurePolicy: 'fail-closed', content: { default: 'body' },
  upload: { endpoint: 'https://upload.test/bytes', maxBytes: 1024, timeoutMs: 1000 }, ...overrides });
const backend = (i, subscriptions = [subscription()]) => ({ id: `test.planning.backend${i}`,
  transport: { type: 'http', url: `https://backend${i}.test/hooks` }, subscriptions });
function client(t, backends, fetch, options = {}) {
  const hooks = new Hooks({ protocolVersion: 'draft', hooks: backends }, {
    source: 'urn:test:upload-planning', capabilities: { 'turn.start': {
      modes: ['intercept', 'observe'], capabilities: { effects: ['deny'] },
    } }, fetch, ...options,
  });
  t.after(() => hooks.close());
  return hooks;
}
const reply = (wire, effects = []) => wire.method === 'hooks/observe' ? new Response(null, { status: 204 })
  : Response.json({ jsonrpc: '2.0', id: wire.id, result: { protocolVersion: 'draft', effects } });
const receipt = (init, ref = 'https://receipt.test/bytes') => Response.json({ ref, size: init.body.byteLength,
  sha256: createHash('sha256').update(init.body).digest('hex') }, { status: 201 });
async function settle(t, hooks, event, options) {
  const result = await hooks.turnStart(event, options);
  t.after(() => result.content?.close());
  await result.observations;
  return result;
}
const lazy = (open = () => new Uint8Array([1, 2, 3]), dispose) => Attachment.lazy(open, dispose);

for (const [label, cap, count] of [['default', undefined, 12], ['configured', 2, 6]]) {
  test(`${label} upload concurrency spans destinations and completes before the first interceptor`, async t => {
    let active = 0, peak = 0, completed = 0, calls = 0;
    const hooks = client(t, Array.from({ length: count }, (_, i) => backend(i)), async (url, init) => {
      if (String(url).includes('upload.test')) {
        active++; peak = Math.max(peak, active);
        await new Promise(resolve => setTimeout(resolve, 15));
        active--; completed++;
        return receipt(init);
      }
      calls++;
      assert.equal(completed, count, 'interception must wait for every selected receipt');
      return reply(JSON.parse(init.body));
    }, cap === undefined ? {} : { maxConcurrentUploads: cap });
    const result = await settle(t, hooks, input(lazy()));
    assert.deepEqual(result.errors, []);
    assert.equal(calls, count);
    assert.equal(peak, cap ?? 8, 'uploads overlap but never exceed the global cap');
  });
}

test('maxConcurrentUploads accepts only positive integers', t => {
  for (const maxConcurrentUploads of [0, -1, 1.5, NaN, Infinity, '2', null]) {
    assert.throws(() => client(t, [backend(0)], async () => new Response(), { maxConcurrentUploads }),
      undefined, `invalid upload cap: ${String(maxConcurrentUploads)}`);
  }
});

test('one immutable lazy snapshot fans out to two routes and duplicate parts share each route receipt', async t => {
  let opens = 0, uploads = 0;
  const wires = [];
  const owner = lazy(() => { opens++; return new Uint8Array([1, 2, 3]); });
  const hooks = client(t, [backend(0), backend(1)], async (url, init) => {
    if (String(url).includes('upload.test')) {
      uploads++;
      assert.deepEqual([...init.body], [1, 2, 3]);
      const response = receipt(init, `https://receipt.test/${uploads}`);
      init.body.fill(0); // A receiver must not mutate the owner's snapshot or another route's bytes.
      return response;
    }
    const wire = JSON.parse(init.body); wires.push(wire); return reply(wire);
  });
  const result = await settle(t, hooks, input(owner, owner));
  assert.deepEqual(result.errors, []);
  assert.equal(opens, 1);
  assert.equal(uploads, 2);
  assert.equal(wires.length, 2);
  for (const wire of wires) assert.equal(wire.params.event.items[0].parts[0].body.ref,
    wire.params.event.items[0].parts[1].body.ref);
  assert.notEqual(wires[0].params.event.items[0].parts[0].body.ref, wires[1].params.event.items[0].parts[0].body.ref);
});

test('subscriptions on the same backend remain distinct receipt destinations', async t => {
  let uploads = 0;
  const refs = [];
  const hooks = client(t, [backend(0, [subscription(), subscription()])], async (url, init) => {
    if (String(url).includes('upload.test')) return receipt(init, `https://receipt.test/${++uploads}`);
    const wire = JSON.parse(init.body); refs.push(wire.params.event.items[0].parts[0].body.ref); return reply(wire);
  });
  assert.deepEqual((await settle(t, hooks, input(lazy()))).errors, []);
  assert.equal(uploads, 2);
  assert.equal(new Set(refs).size, 2);
});

for (const selection of ['metadata', 'omit']) test(`${selection} and unmatched body routes do not open lazy sources`, async t => {
  let opens = 0, uploads = 0, calls = 0;
  const hooks = client(t, [backend(0, [subscription({ content: { default: selection } })]),
    backend(1, [subscription({ events: ['tool.before'] })])], async (url, init) => {
    if (String(url).includes('upload.test')) { uploads++; return receipt(init); }
    calls++; return reply(JSON.parse(init.body));
  }, { capabilities: { 'turn.start': { modes: ['intercept'], capabilities: { effects: [] } }, 'tool.before': { effects: [] } } });
  assert.deepEqual((await settle(t, hooks, input(lazy(() => { opens++; throw Error('no demand'); })))).errors, []);
  assert.equal(opens, 0); assert.equal(uploads, 0); assert.equal(calls, 1);
});

for (const failurePolicy of ['fail-open', 'fail-closed']) test(`failed upload is deferred to its ${failurePolicy} route without poisoning healthy receipts`, async t => {
  const calls = [], uploads = [];
  const hooks = client(t, [backend(0, [subscription({ upload: { ...subscription().upload, endpoint: 'https://healthy.test/upload' } })]),
    backend(1, [subscription({ failurePolicy, upload: { ...subscription().upload, endpoint: 'https://broken.test/upload' } })])], async (url, init) => {
    if (String(url).endsWith('/upload')) {
      uploads.push(String(url));
      if (String(url).includes('broken')) throw Error('receiver unavailable');
      return receipt(init);
    }
    calls.push(String(url)); return reply(JSON.parse(init.body));
  });
  const result = await settle(t, hooks, input(lazy()));
  assert.equal(uploads.length, 2);
  assert.deepEqual(calls, ['https://backend0.test/hooks']);
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].backendId, 'test.planning.backend1');
  assert.equal(result.errors[0].syntheticDenial, failurePolicy === 'fail-closed');
});

test('early denial suppresses later interception and reuses its preuploaded receipt for settled observation', async t => {
  let uploads = 0;
  const calls = [];
  const hooks = client(t, [backend(0), backend(1)], async (url, init) => {
    if (String(url).includes('upload.test')) return receipt(init, `https://receipt.test/${++uploads}`);
    const wire = JSON.parse(init.body); calls.push({ url: String(url), wire });
    return reply(wire, [{ type: 'deny', reason: 'policy' }]);
  });
  const result = await settle(t, hooks, input(lazy()));
  assert.deepEqual(result.errors, []);
  assert.equal(uploads, 2);
  assert.deepEqual(calls.map(x => x.wire.method), ['hooks/intercept', 'hooks/observe']);
  assert.equal(calls[1].url, 'https://backend1.test/hooks');
  assert.equal(calls[1].wire.params.event.items[0].parts[0].body.ref, 'https://receipt.test/2');
});

test('early denial does not turn an uncalled route upload failure into synthetic denial', async t => {
  let uploads = 0;
  const calls = [];
  const hooks = client(t, [backend(0), backend(1)], async (url, init) => {
    if (String(url).includes('upload.test')) {
      if (++uploads === 2) throw Error('second destination unavailable');
      return receipt(init);
    }
    const wire = JSON.parse(init.body); calls.push(wire.method);
    return reply(wire, [{ type: 'deny', reason: 'original policy' }]);
  });
  const result = await settle(t, hooks, input(lazy()));
  assert.equal(uploads, 2);
  assert.deepEqual(calls, ['hooks/intercept']);
  assert.deepEqual(result.response.result.effects.filter(e => e.type === 'deny'), [{ type: 'deny', reason: 'original policy' }]);
  assert.ok(result.errors.every(e => !e.syntheticDenial));
});

test('equal upload URLs still authenticate and cache receipts separately per backend', async t => {
  const authCalls = [], uploads = [], refs = [];
  const auth = { credential(context) {
    authCalls.push({ backend: context.backendId, purpose: context.purpose });
    return context.purpose === 'upload' ? { type: 'bearer', token: context.backendId } : undefined;
  }, challenge() { assert.fail('unexpected challenge'); } };
  const hooks = client(t, [0, 1].map(i => backend(i, [subscription({ upload: {
    ...subscription().upload, auth: { type: 'bearer', tokenRef: 'upload-token' },
  } })])), async (url, init) => {
    if (String(url).includes('upload.test')) {
      const token = new Headers(init.headers).get('authorization'); uploads.push(token);
      return receipt(init, `https://receipt.test/${token.slice(7)}`);
    }
    assert.equal(new Headers(init.headers).get('authorization'), null, 'upload identity must not leak into event requests');
    const wire = JSON.parse(init.body); refs.push(wire.params.event.items[0].parts[0].body.ref); return reply(wire);
  }, { auth });
  assert.deepEqual((await settle(t, hooks, input(lazy()))).errors, []);
  assert.deepEqual(uploads.sort(), ['Bearer test.planning.backend0', 'Bearer test.planning.backend1']);
  assert.equal(authCalls.filter(c => c.purpose === 'upload').length, 2);
  assert.equal(new Set(refs).size, 2);
});

test('attachment removal can waste preupload without reintroducing removed content', async t => {
  let uploads = 0;
  const wires = [];
  const hooks = client(t, [backend(0), backend(1)], async (url, init) => {
    if (String(url).includes('upload.test')) return receipt(init, `https://receipt.test/${++uploads}`);
    const wire = JSON.parse(init.body); wires.push(wire);
    return reply(wire, wires.length === 1 ? [{ type: 'modify', target: 'prompt', operation: 'replace',
      value: [{ id: 'replacement', role: 'user', parts: [{ id: 'text', kind: 'text', mediaType: 'text/plain', selection: 'body', text: 'removed' }] }] }] : []);
  }, { capabilities: { 'turn.start': { modes: ['intercept', 'observe'], capabilities: {
    effects: ['modify'], modify: { prompt: { replace: true, merge: false } },
  } } } });
  const result = await settle(t, hooks, input(lazy()));
  assert.deepEqual(result.errors, []);
  assert.equal(uploads, 2);
  assert.equal(wires[1].params.event.items[0].parts[0].kind, 'text');
  assert.equal(result.event.items[0].parts[0].text, 'removed');
});

test('cancellation aborts preupload source work and disposes its owner exactly once', async t => {
  const controller = new AbortController();
  let opened, closes = 0, aborted = 0, requests = 0;
  const started = new Promise(resolve => { opened = resolve; });
  const owner = lazy(signal => {
    opened();
    return new Promise((_, reject) => signal.addEventListener('abort', () => {
      aborted++; reject(signal.reason);
    }, { once: true }));
  }, () => { closes++; });
  const hooks = client(t, [backend(0), backend(1)], async () => { requests++; throw Error('unexpected request'); });
  const pending = hooks.turnStart(input(owner, owner), { signal: controller.signal });
  await started;
  controller.abort(new Error('cancelled test operation'));
  const result = await pending;
  await result.content.close();
  await result.content.close();
  await hooks.close();
  assert.equal(result.interrupted, true);
  assert.equal(requests, 0); assert.equal(aborted, 1); assert.equal(closes, 1);
});

test('explicit mode grants reject unauthorized observation before any source or network work', async t => {
  let opens = 0, calls = 0;
  const hooks = client(t, [backend(0, [{ mode: 'observe', events: ['turn.start'],
    content: { default: 'body' }, upload: subscription().upload }])], async () => {
    calls++; throw Error('unauthorized delivery');
  }, { capabilities: { 'turn.start': { modes: ['intercept'], capabilities: { effects: [] } } } });
  await assert.rejects(hooks.turnStart(input(lazy(() => { opens++; throw Error('unauthorized read'); }))),
    error => error.issues?.some(issue => issue.code === 'NOT_OBSERVABLE'));
  assert.equal(opens, 0); assert.equal(calls, 0);
});

test('no selected destinations leave a lazy source unread until explicit result disposal', async t => {
  let opens = 0, closes = 0;
  const hooks = client(t, [backend(0, [subscription({ events: ['tool.before'] })])],
    async () => { throw Error('no destination'); }, { capabilities: {
      'turn.start': { effects: [] }, 'tool.before': { effects: [] },
    } });
  const result = await settle(t, hooks, input(lazy(() => { opens++; throw Error('no demand'); }, () => { closes++; })));
  assert.deepEqual(result.errors, []);
  assert.equal(opens, 0); assert.equal(closes, 0);
  await result.content.close();
  assert.equal(closes, 1);
});

for (const [key, projection] of [['paths', { path: 'private/file' }], ['toolKinds', { tool: { kind: 'write' } }]]) {
  test(`${key} filters exclude known mismatches before attachment demand`, async t => {
    let opens = 0, calls = 0;
    const hooks = client(t, [backend(0, [subscription({ filters: { [key]: ['read'] } })])], async () => {
      calls++; throw Error('filtered route must not deliver');
    });
    const event = input(lazy(() => { opens++; return new Uint8Array([1]); }));
    event.items[0].id = 'message';
    event.items[0].parts[0].id = 'part';
    event.items[0].parts[0].selection = 'body';
    const result = await hooks.dispatch('turn.start', { ...event, ...projection });
    t.after(() => result.content?.close());
    assert.deepEqual(result.errors, []);
    assert.equal(opens, 0); assert.equal(calls, 0);
  });
}
test('missing filter projections retain authorized routes', async t => {
  let uploads = 0;
  const hooks = client(t, [backend(0, [subscription({ filters: { paths: ['read'], toolKinds: ['read'] } })])], async (url, init) => {
    if (String(url).includes('upload.test')) { uploads++; return receipt(init); }
    return reply(JSON.parse(init.body));
  });
  assert.deepEqual((await settle(t, hooks, input(lazy()))).errors, []);
  assert.equal(uploads, 1);
});

for (const substitute of [false, true]) test(substitute ? 'effects cannot substitute new binary refs' : 'attachment reordering preserves immutable owners and receiver-local receipts', async t => {
  let uploads = 0;
  const wires = [];
  const hooks = client(t, [backend(0), backend(1)], async (url, init) => {
    if (String(url).includes('upload.test')) return receipt(init, `https://receipt.test/${++uploads}`);
    const wire = JSON.parse(init.body); wires.push(wire);
    if (wires.length !== 1) return reply(wire);
    const items = structuredClone(wire.params.event.items);
    items[0].parts.reverse();
    if (substitute) items[0].parts[0].body.ref = 'https://foreign.test/created';
    return reply(wire, [{ type: 'modify', target: 'prompt', operation: 'replace', value: items }]);
  }, { capabilities: { 'turn.start': { modes: ['intercept', 'observe'], capabilities: {
    effects: ['modify'], modify: { prompt: { replace: true, merge: false } },
  } } } });
  const result = await settle(t, hooks, input(lazy(() => new Uint8Array([1])), lazy(() => new Uint8Array([2]))));
  assert.equal(uploads, 4);
  if (substitute) {
    assert.equal(result.errors.length, 1);
    assert.equal(result.errors[0].phase, 'interception');
    assert.equal(result.permission, 'deny');
  } else {
    assert.deepEqual(result.errors, []);
    assert.deepEqual(wires[1].params.event.items[0].parts.map(p => p.id), wires[0].params.event.items[0].parts.map(p => p.id).reverse());
    assert.ok(wires[1].params.event.items[0].parts.every(p => !wires[0].params.event.items[0].parts.some(original => original.body.ref === p.body.ref)));
    assert.deepEqual(await result.content.read(result.event.items[0].parts[0].id), new Uint8Array([2]));
  }
});
test('inline text body demand never uploads', async t => {
  let uploads = 0;
  const hooks = client(t, [backend(0)], async (url, init) => {
    if (String(url).includes('upload.test')) { uploads++; throw Error('text cannot upload'); }
    const wire = JSON.parse(init.body);
    assert.equal(wire.params.event.items[0].parts[0].text, 'inline');
    return reply(wire);
  });
  const result = await settle(t, hooks, { turn: { id: 'turn' }, trigger: 'user', items: [{ role: 'user', parts: [{ kind: 'text', text: 'inline' }] }] });
  assert.deepEqual(result.errors, []); assert.equal(uploads, 0);
});

test('timed-out raw source preparation settles and releases unfinished source work', { timeout: 2000 }, async t => {
  let cancels = 0, uploads = 0;
  const stream = new ReadableStream({
    pull() { return new Promise(() => {}); },
    cancel() { cancels++; },
  }, { highWaterMark: 0 });
  const hooks = client(t, [backend(0, [subscription({ failurePolicy: 'fail-open', upload: { ...subscription().upload, timeoutMs: 20 } })])], async () => {
    uploads++; throw Error('unfinished source must not send');
  });
  const result = await hooks.dispatch('turn.start', { turn: { id: 'turn' }, trigger: 'user', items: [{ id: 'message', role: 'user', parts: [{ id: 'part', kind: 'attachment', mediaType: 'application/octet-stream', selection: 'body', body: stream }] }] });
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].phase, 'preparation');
  assert.equal(uploads, 0); assert.equal(cancels, 1);
  assert.equal(stream.locked, false);
  assert.equal(result.event.items[0].parts[0].selection, 'metadata');
});

// Yield to the next event-loop turn so all immediately runnable planning work drains.
const uploadPlanningTurn = () => new Promise(resolve => setImmediate(resolve));

for (const cap of [undefined, 2, 12]) {
  test(`simultaneous boundaries share the ${cap ?? 'default'} upload cap`, { timeout: 3000 }, async t => {
    const expectedCap = cap ?? 8;
    let release, filled, active = 0, peak = 0, uploads = 0;
    const capacityFilled = new Promise(resolve => { filled = resolve; });
    const gate = new Promise(resolve => { release = resolve; });
    t.after(() => release());
    const hooks = client(t, Array.from({ length: expectedCap + 1 }, (_, i) => backend(i)), async (url, init) => {
      if (!String(url).includes('upload.test')) return reply(JSON.parse(init.body));
      uploads++; active++; peak = Math.max(peak, active);
      if (active === expectedCap) filled();
      try {
        await gate;
        return receipt(init);
      } finally { active--; }
    }, cap === undefined ? {} : { maxConcurrentUploads: cap });
    const pending = [settle(t, hooks, input(lazy())), settle(t, hooks, input(lazy()))];
    await capacityFilled;
    await uploadPlanningTurn();
    assert.equal(active, expectedCap, 'all boundaries together fill, but do not exceed, the cap');
    release();
    const results = await Promise.all(pending);
    for (const result of results) assert.deepEqual(result.errors, []);
    assert.equal(uploads, 2 * (expectedCap + 1));
    assert.equal(peak, expectedCap);
    assert.equal(active, 0);
  });
}

test('a shared upload slot covers materialization through confirmed transfer', { timeout: 3000 }, async t => {
  let finishSource, confirmTransfer, transferStarted, opens = 0, uploads = 0;
  const transferring = new Promise(resolve => { transferStarted = resolve; });
  const sourceGate = new Promise(resolve => { finishSource = resolve; });
  const transferGate = new Promise(resolve => { confirmTransfer = resolve; });
  t.after(() => { finishSource(); confirmTransfer(); });
  const hooks = client(t, [backend(0)], async (url, init) => {
    if (!String(url).includes('upload.test')) return reply(JSON.parse(init.body));
    uploads++;
    if (init.body[0] === 1) { transferStarted(); await transferGate; }
    return receipt(init);
  }, { maxConcurrentUploads: 1 });
  const first = settle(t, hooks, input(lazy(async () => {
    opens++; await sourceGate; return new Uint8Array([1]);
  })));
  await uploadPlanningTurn();
  const second = settle(t, hooks, input(lazy(() => { opens++; return new Uint8Array([2]); })));
  await uploadPlanningTurn();
  assert.equal(opens, 1, 'queued boundaries must not materialize their sources');
  assert.equal(uploads, 0);
  finishSource();
  await transferring;
  await uploadPlanningTurn();
  assert.equal(uploads, 1);
  assert.equal(opens, 1, 'the slot remains occupied until the transfer confirms');
  confirmTransfer();
  for (const result of await Promise.all([first, second])) assert.deepEqual(result.errors, []);
  assert.equal(opens, 2); assert.equal(uploads, 2);
});

for (const cancellation of ['queued', 'active']) {
  test(`cancelling ${cancellation === 'active' ? 'an' : 'a'} ${cancellation} boundary preserves FIFO progress for healthy boundaries`, { timeout: 3000 }, async t => {
    const controller = new AbortController();
    let release, uploadStarted, active = 0, peak = 0;
    const started = new Promise(resolve => { uploadStarted = resolve; });
    const gate = new Promise(resolve => { release = resolve; });
    const order = [], opened = [];
    t.after(() => release());
    const hooks = client(t, [backend(0)], async (url, init) => {
      if (!String(url).includes('upload.test')) return reply(JSON.parse(init.body));
      const id = init.body[0];
      order.push(id); active++; peak = Math.max(peak, active);
      if (id === 1) uploadStarted();
      try {
        if (id === 1) await new Promise((resolve, reject) => {
          const abort = () => reject(init.signal.reason);
          init.signal.addEventListener('abort', abort, { once: true });
          gate.then(() => { init.signal.removeEventListener('abort', abort); resolve(); });
          if (init.signal.aborted) abort();
        });
        return receipt(init);
      } finally { active--; }
    }, { maxConcurrentUploads: 1 });
    const event = id => input(lazy(() => { opened.push(id); return new Uint8Array([id]); }));
    const first = settle(t, hooks, event(1), cancellation === 'active' ? { signal: controller.signal } : undefined);
    await started;
    assert.deepEqual(order, [1]);
    const cancelled = cancellation === 'queued'
      ? settle(t, hooks, event(2), { signal: controller.signal }) : first;
    const healthy = [settle(t, hooks, event(3)), settle(t, hooks, event(4))];
    await uploadPlanningTurn();
    assert.deepEqual(opened, [1]);
    controller.abort(new Error(`cancel ${cancellation} boundary`));
    assert.equal((await cancelled).interrupted, true);
    release();
    const results = await Promise.all([first, ...healthy]);
    for (const result of results.slice(cancellation === 'active' ? 1 : 0)) assert.deepEqual(result.errors, []);
    assert.deepEqual(order, [1, 3, 4], 'cancelled queue entries do not consume a slot or reorder waiters');
    assert.deepEqual(opened, [1, 3, 4]);
    assert.equal(peak, 1); assert.equal(active, 0);
  });
}
