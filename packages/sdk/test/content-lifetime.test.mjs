import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Attachment, Hooks } from "agenthooksprotocol/client";

const requestType = "user.elicitation.request";
const resultType = "user.elicitation.result";
const binary = new Uint8Array([255, 0, 1]);
const body = () => new ReadableStream({
  start(c) { c.enqueue(binary.slice()); c.close(); },
});
const item = (value) => ({ id: "request-text", kind: "text", mediaType: "text/plain", selection: "body", text: JSON.stringify(value) });
const attachment = () => ({ id: "body", kind: "attachment", mediaType: "application/octet-stream", body: body() });
const request = (id, session = "one") => ({
  id, session: { id: session }, items: [attachment()],
  elicitation: { mode: "form", server: "test", request: item({ message: "Answer?", requestedSchema: { type: "object", properties: {} } }) },
});
function client({ effects = () => [], fetchHook, maxContentBytes } = {}) {
  return new Hooks({ protocolVersion: "draft", hooks: [{
    id: "test.lifetime", transport: { type: "http", url: "https://test.example/hooks" },
    subscriptions: [{ mode: "intercept", events: [requestType, resultType], timeoutMs: 1000,
      failurePolicy: "fail-open", content: { default: "body" },
      upload: { endpoint: "https://test.example/upload", timeoutMs: 1000, maxBytes: 4096 } }],
  }] }, {
    source: "urn:test:lifetime", maxContentBytes,
    capabilities: {
      [requestType]: { effects: ["return", "deny"], elicitation: { form: {} } },
      [resultType]: { effects: ["modify"], modify: { content: { replace: true, append: false, merge: false } }, elicitation: { form: {} } },
      "session.end": { modes: ["observe"] },
    },
    fetch: async (url, init) => {
      if (String(url).endsWith("/upload")) {
        const bytes = Buffer.from(await new Response(init.body).arrayBuffer());
        return Response.json({ ref: "urn:test:body", size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") }, { status: 201 });
      }
      const req = JSON.parse(init.body);
      if (fetchHook) await fetchHook(req, init);
      return Response.json({ jsonrpc: "2.0", id: req.id, result: { protocolVersion: "draft", effects: effects(req.params.event) } });
    },
  });
}
const empty = (hooks) => {
  assert.equal(hooks.elicitations.size, 0);
  assert.equal(hooks.elicitationBytes, 0);
  assert.equal(hooks.managers.size, 0);
  assert.equal(hooks.pending.size, 0);
  assert.equal(hooks.activeElicitations.size, 0);
};

test("4097 terminal invocations release bookkeeping while result views retain owners", async () => {
  const hooks = client({ effects: () => [{ type: "deny", reason: "Policy" }] });
  const results = [];
  try {
    for (let i = 0; i < 4097; i++) {
      const result = await hooks.dispatch(requestType, request(`request-${i}`));
      assert.deepEqual(result.errors, []);
      results.push(result);
      empty(hooks);
      assert.equal(typeof result.event.elicitation.request.text, "string");
      assert.ok(result.event.items[0].body instanceof ReadableStream);
    }
    assert.deepEqual(results[0].response.result.effects, [{ type: "deny", reason: "Policy" }]);
    assert.deepEqual(new Uint8Array(await new Response(results[0].event.items[0].body).arrayBuffer()), binary);
  } finally {
    await Promise.all(results.map(result => result.event.items[0].body.cancel().catch(() => {})));
    await hooks.close();
  }
});

test("pending exchanges retain only required bytes; dropping one preserves another", async () => {
  const hooks = client();
  try {
    const input = request("first");
    input.native = { unrelated: "large host state" };
    await hooks.dispatch(requestType, input);
    await hooks.dispatch(requestType, request("second", "two"));
    const entry = hooks.elicitations.get("first");
    assert.equal(entry.event.native, undefined);
    assert.equal(entry.event.elicitation.request.body, undefined);
    assert.ok(entry.size > 0);
    hooks.discardElicitation("first");
    assert.deepEqual([...hooks.elicitations.keys()], ["second"]);
    hooks.discardElicitation("second");
    empty(hooks);
  } finally { await hooks.close(); }
});

for (const mode of ["invalid", "aborted", "timeout", "failure"])
  test(`result ${mode} retires only its correlated exchange`, async () => {
    const hooks = client({ fetchHook: async (req) => {
      if (req.params.event.type !== resultType) return;
      if (mode === "failure") throw Error("offline");
      if (mode === "timeout") await new Promise(() => {});
    } });
    try {
      await hooks.dispatch(requestType, request("first"));
      await hooks.dispatch(requestType, request("second"));
      const controller = new AbortController();
      if (mode === "aborted") controller.abort();
      const input = { items: [], id: "result", parentEventId: "first", session: { id: "one" },
        elicitation: { action: "decline", mode: "form", server: "test", result: item({ action: "decline" }) } };
      if (mode === "invalid") delete input.elicitation;
      const work = hooks.dispatch(resultType, input, { signal: mode === "timeout" ? AbortSignal.timeout(20) : controller.signal });
      if (mode === "invalid") await assert.rejects(work);
      else await work;
      assert.deepEqual([...hooks.elicitations.keys()], ["second"]);
      hooks.discardElicitation("second");
      empty(hooks);
    } finally { await hooks.close(); }
  });

test("active exchange capacity errors rather than evicting unfinished requests", async () => {
  const hooks = client();
  try {
    for (let i = 0; i < 128; i++) {
      const result = await hooks.dispatch(requestType, request(`pending-${i}`));
      assert.deepEqual(result.errors, []);
    }
    const overflow = await hooks.dispatch(requestType, request("overflow"));
    assert.equal(overflow.errors[0].code, "PREPARATION_FAILED");
    assert.equal(hooks.elicitations.size, 128);
    assert.ok(hooks.elicitations.has("pending-0"));
    assert.equal(hooks.elicitations.has("overflow"), false);
  } finally { await hooks.close(); }
  empty(hooks);
});

test("active exchange byte budget remains enforced", async () => {
  const hooks = client({ maxContentBytes: 100 });
  try {
    assert.deepEqual((await hooks.dispatch(requestType, request("first"))).errors, []);
    assert.equal((await hooks.dispatch(requestType, request("second"))).errors[0].code, "PREPARATION_FAILED");
    assert.deepEqual([...hooks.elicitations.keys()], ["first"]);
  } finally { await hooks.close(); }
});


test("successful correlated inline replacement survives retirement", async () => {
  const replacement = { answer: "replacement" };
  const hooks = client({ effects: (event) => event.type === resultType
    ? [{ type: "modify", target: "content", operation: "replace", value: replacement }] : [] });
  try {
    await hooks.dispatch(requestType, request("first"));
    const result = await hooks.dispatch(resultType, {
      items: [], id: "answer", parentEventId: "first", session: { id: "one" },
      elicitation: { mode: "form", server: "test", action: "accept", result: item({ action: "accept", content: {} }) },
    });
    assert.deepEqual(result.errors, []);
    empty(hooks);
    assert.deepEqual(JSON.parse(result.event.elicitation.result.text), { action: "accept", content: { answer: "replacement" } });
    assert.deepEqual(result.response.result.effects[0].value, { answer: "replacement" });
    replacement.answer = "mutated";
    assert.deepEqual(result.response.result.effects[0].value, { answer: "replacement" });
  } finally { await hooks.close(); }
});

test("concurrent pending requests have isolated ownership and session retirement", async () => {
  let release, entered;
  const gate = new Promise((r) => { release = r; });
  const started = new Promise((r) => { entered = r; });
  const hooks = client({ fetchHook: async (req) => {
    if (req.params.event.id === "slow") { entered(); await gate; }
  } });
  try {
    const pending = hooks.dispatch(requestType, request("slow", "slow-session"));
    await started;
    const manager = [...hooks.managers][0];
    assert.ok(manager.budget.used > 0);
    await hooks.dispatch(requestType, request("fast", "fast-session"));
    assert.ok(hooks.elicitations.has("slow"));
    assert.ok(hooks.elicitations.has("fast"));
    hooks.discardElicitation("fast");
    assert.ok(manager.budget.used > 0);
    release();
    await pending;
    assert.equal(manager.attachments.size, 0);
    assert.equal("snapshots" in manager, false);
    assert.equal("readers" in manager, false);
    const signal = AbortSignal.abort();
    await hooks.dispatch("session.end", { session: { id: "slow-session" } }, { signal });
    empty(hooks);
  } finally { release(); await hooks.close(); }
});

for (const mode of ["deny", "failure", "abort", "timeout"])
  test(`request ${mode} releases its retained exchange and manager`, async () => {
    const controller = new AbortController();
    let manager;
    const hooks = client({
      effects: () => mode === "deny" ? [{ type: "deny", reason: "Policy" }] : [],
      fetchHook: async () => {
        manager = [...hooks.managers][0];
        assert.ok(manager.budget.used > 0);
        if (mode === "failure") throw Error("offline");
        if (mode === "abort") controller.abort();
        if (mode === "timeout") await new Promise(() => {});
      },
    });
    try {
      const result = await hooks.dispatch(requestType, request("request"), {
        signal: mode === "timeout" ? AbortSignal.timeout(30) : controller.signal,
      });
      empty(hooks);
      assert.equal(manager.attachments.size, 0);
      assert.equal("readers" in manager, false);
      assert.equal("snapshots" in manager, false);
      assert.equal(typeof result.event.elicitation.request.text, "string");
      assert.ok(result.event.items[0].body instanceof ReadableStream);
    } finally { await hooks.close(); }
  });

function gatedRequest(id, session) {
  let enter, release;
  let cancelled = false;
  const entered = new Promise((resolve) => { enter = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const input = request(id, session);
  input.items[0].body = new ReadableStream({
    async pull(controller) {
      enter();
      await gate;
      if (cancelled) return;
      controller.enqueue(binary.slice());
      controller.close();
    },
    cancel() { cancelled = true; },
  }, { highWaterMark: 0 });
  return { input, entered, release };
}

for (const retirement of ["discard", "session.end", "session.end-generated", "result", "close"])
  test(`${retirement} prevents late retention from gated request preparation`, async () => {
    const hooks = client();
    const slow = gatedRequest(retirement === "session.end-generated" ? undefined : "racy", "ended");
    const other = gatedRequest("unrelated", "live");
    const pending = hooks.dispatch(requestType, slow.input);
    const unrelated = hooks.dispatch(requestType, other.input);
    try {
      await Promise.all([slow.entered, other.entered]);
      assert.equal(hooks.activeElicitations.size, 2);
      assert.equal(hooks.elicitations.size, 0);
      if (retirement === "discard") hooks.discardElicitation("racy");
      else if (retirement.startsWith("session.end"))
        await hooks.dispatch("session.end", { session: { id: "ended" } }, { signal: AbortSignal.abort() });
      else if (retirement === "result")
        await hooks.dispatch(resultType, { parentEventId: "racy" }, { signal: AbortSignal.abort() });
      else await hooks.close();
      slow.release();
      other.release();
      const [result, otherResult] = await Promise.all([pending, unrelated]);
      assert.equal(hooks.activeElicitations.size, 0);
      assert.equal(hooks.elicitations.has("racy"), false);
      if (retirement === "close") {
        assert.equal(result.interrupted, true);
        empty(hooks);
      } else {
        assert.deepEqual(result.errors, []);
        assert.deepEqual(otherResult.errors, []);
        assert.deepEqual([...hooks.elicitations.keys()], ["unrelated"]);
        assert.equal(hooks.elicitationBytes, hooks.elicitations.get("unrelated").size);
        hooks.discardElicitation("unrelated");
        empty(hooks);
        // Retirement leaves no historical tombstone that blocks a later call.
        const next = await hooks.dispatch(requestType, request("racy", "ended"));
        assert.deepEqual(next.errors, []);
        assert.equal(hooks.elicitations.has("racy"), true);
        hooks.discardElicitation("racy");
        empty(hooks);
      }
    } finally {
      slow.release();
      other.release();
      await Promise.allSettled([pending, unrelated]);
      await hooks.close();
    }
  });
test('binary result ownership survives inline protocol correlation retirement', async () => {
  const hooks = client();
  const input = request('shared-owner');
  input.items[0].body = Attachment.fromStream(input.items[0].body);
  const result = await hooks.dispatch(requestType, input);
  const entry = hooks.elicitations.get('shared-owner');
  assert.equal('bytes' in entry, false);
  let reads = 0;
  const owner = result.content.bodies.get('body').owner;
  const originalRead = owner.read.bind(owner);
  owner.read = (...args) => { reads++; return originalRead(...args); };
  hooks.discardElicitation('shared-owner');
  await hooks.close();
  assert.equal(reads, 0);
  assert.deepEqual(await result.content.read('body'), binary);
  assert.equal(reads, 1);
  await result.content.close();
  await assert.rejects(originalRead(), /closed/);
});
test('active correlated composition retains its owner after pending exchange retirement', async () => {
  let hooks;
  hooks = client({
    effects: event => event.type === resultType ? [{ type: 'modify', target: 'content', operation: 'replace', value: { answer: 'retained' } }] : [],
    fetchHook: req => {
      if (req.params.event.type === resultType) hooks.discardElicitation('borrowed');
    },
  });
  const initial = await hooks.dispatch(requestType, request('borrowed'));
  // Remove the result stream lease, leaving only the pending exchange lease.
  await initial.event.items[0].body.cancel();
  const result = await hooks.dispatch(resultType, {
    items: [], id: 'answer', parentEventId: 'borrowed', session: { id: 'one' },
    elicitation: { mode: 'form', server: 'test', action: 'accept', result: item({ action: 'accept', content: {} }) },
  });
  assert.deepEqual(result.errors, []);
  await hooks.close();
  assert.deepEqual(JSON.parse(result.event.elicitation.result.text), { action: 'accept', content: { answer: 'retained' } });
});
