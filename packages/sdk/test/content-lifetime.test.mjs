import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Hooks } from "agenthooksprotocol/client";

const requestType = "user.elicitation.request";
const resultType = "user.elicitation.result";
const body = (value) => new ReadableStream({
  start(c) { c.enqueue(new TextEncoder().encode(JSON.stringify(value))); c.close(); },
});
const item = (value) => ({ id: "body", kind: "text", role: "user", mediaType: "application/json", body: body(value) });
const request = (id, session = "one") => ({
  id, session: { id: session },
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
};

test("4097 terminal public invocations release snapshots even with retained results", async () => {
  const hooks = client({ effects: () => [{ type: "deny", reason: "Policy" }] });
  const results = [];
  try {
    for (let i = 0; i < 4097; i++) {
      const result = await hooks.dispatch(requestType, request(`request-${i}`));
      assert.deepEqual(result.errors, []);
      results.push(result);
      empty(hooks);
      assert.ok(result.event.elicitation.request.body instanceof ReadableStream);
    }
    assert.deepEqual(results[0].response.result.effects, [{ type: "deny", reason: "Policy" }]);
    assert.equal((await new Response(results[0].event.elicitation.request.body).json()).message, "Answer?");
  } finally { await hooks.close(); }
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
    assert.ok(entry.bytes.length > 0);
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
      const input = { id: "result", parentEventId: "first", session: { id: "one" },
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
      id: "answer", parentEventId: "first", session: { id: "one" },
      elicitation: { mode: "form", server: "test", action: "accept", result: item({ action: "accept", content: {} }) },
    });
    assert.deepEqual(result.errors, []);
    empty(hooks);
    assert.deepEqual(await new Response(result.event.elicitation.result.body).json(), { action: "accept", content: { answer: "replacement" } });
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
    assert.ok(manager.retainedBytes > 0);
    await hooks.dispatch(requestType, request("fast", "fast-session"));
    assert.ok(hooks.elicitations.has("slow"));
    assert.ok(hooks.elicitations.has("fast"));
    hooks.discardElicitation("fast");
    assert.ok(manager.retainedBytes > 0);
    release();
    await pending;
    assert.equal(manager.retainedBytes, 0);
    assert.equal(manager.seenStreams.size, 0);
    assert.equal(manager.readers.size, 0);
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
        assert.ok(manager.retainedBytes > 0);
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
      assert.equal(manager.retainedBytes, 0);
      assert.equal(manager.readers.size, 0);
      assert.equal(manager.seenStreams.size, 0);
      assert.ok(result.event.elicitation.request.body instanceof ReadableStream);
    } finally { await hooks.close(); }
  });
