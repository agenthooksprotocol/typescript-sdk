import test from "node:test";
import assert from "node:assert/strict";
import { Hooks, ContentSource } from "agenthooksprotocol/client";

const input = () => ({
  call: { id: "call" },
  path: "native",
  tool: { name: "test", origin: "native", input: { x: 1 } },
});
const subscription = {
  mode: "intercept",
  events: ["tool.before"],
  timeoutMs: 10000,
  failurePolicy: "fail-closed",
  content: { default: "metadata" },
};
function client({
  fetch,
  auth,
  subscriptions = [subscription],
  ...options
} = {}) {
  return new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "test.operation",
          transport: { type: "http", url: "https://example.test/hooks" },
          subscriptions,
        },
      ],
    },
    {
      source: "urn:test:operation",
      capabilities: {
        "session.end": { modes: ["observe"] },
        "tool.before": {
          modes: ["intercept", "observe"],
          capabilities: {
            effects: ["allow", "modify"],
            modify: { input: { replace: true, merge: false } },
          },
        },
      },
      fetch,
      auth,
      ...options,
    },
  );
}
const reply = (init, effects) =>
  Response.json({
    jsonrpc: "2.0",
    id: JSON.parse(init.body).id,
    result: { protocolVersion: "draft", effects },
  });
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

test("result input and permission use accepted settlement, not original host arguments", async () => {
  const hooks = client({
    fetch: async (_, init) =>
      reply(init, [
        {
          type: "modify",
          target: "input",
          operation: "replace",
          value: { x: 2 },
        },
        { type: "allow" },
      ]),
  });
  const original = input();
  try {
    const result = await hooks.dispatch("tool.before", original);
    assert.equal(result.permission, "allow");
    assert.deepEqual(result.input, { x: 2 });
    assert.deepEqual(original.tool.input, { x: 1 });
    assert.deepEqual(result.diagnostics, []);
  } finally {
    await hooks.close();
  }
});

test("the call remains pending until owned observation delivery settles", async () => {
  const entered = deferred(),
    release = deferred();
  let completed = false;
  const hooks = client({
    subscriptions: [
      {
        mode: "observe",
        events: ["tool.before"],
        content: { default: "metadata" },
      },
    ],
    fetch: async () => {
      entered.resolve();
      await release.promise;
      return new Response(null, { status: 204 });
    },
  });
  try {
    const work = hooks.dispatch("tool.before", input()).then((result) => {
      completed = true;
      return result;
    });
    await entered.promise;
    assert.equal(completed, false);
    release.resolve();
    const result = await work;
    assert.equal(completed, true);
    assert.deepEqual(result.diagnostics, []);
    assert.deepEqual(await result.observations, []);
  } finally {
    release.resolve();
    await hooks.close();
  }
});

for (const timeout of [false, true])
  test(`outer ${timeout ? "deadline" : "cancellation"} bounds auth wait and prevents delivery`, async () => {
    const entered = deferred();
    const controller = new AbortController();
    let sent = 0,
      providerSignal;
    const hooks = client({
      auth: {
        credential(context) {
          providerSignal = context.signal;
          entered.resolve();
          return new Promise(() => {});
        },
        challenge() {},
      },
      fetch: async () => {
        sent++;
        throw new Error("unexpected delivery");
      },
    });
    try {
      const work = hooks.dispatch("tool.before", input(), {
        signal: controller.signal,
      });
      await entered.promise;
      controller.abort(
        new DOMException("stopped", timeout ? "TimeoutError" : "AbortError"),
      );
      const result = await work;
      assert.equal(providerSignal.aborted, true);
      assert.equal(result.interrupted, true);
      assert.equal(
        result.errors[0].code,
        timeout ? "DEADLINE_EXCEEDED" : "INTERRUPTED",
      );
      assert.equal(result.errors[0].syntheticDenial, false);
      assert.equal(sent, 0);
      assert.equal(result.permission, "none");
    } finally {
      await hooks.close();
    }
  });

test("close cancels owned observation I/O without closing shared providers", async () => {
  const entered = deferred();
  let providerClosed = false;
  const hooks = client({
    subscriptions: [
      {
        mode: "observe",
        events: ["tool.before"],
        content: { default: "metadata" },
      },
    ],
    auth: {
      credential() {
        return undefined;
      },
      challenge() {},
      close() {
        providerClosed = true;
      },
    },
    fetch: async (_, init) => {
      entered.resolve();
      return new Promise((_, reject) =>
        init.signal.addEventListener(
          "abort",
          () => reject(init.signal.reason),
          { once: true },
        ),
      );
    },
  });
  const work = hooks.dispatch("tool.before", input());
  await entered.promise;
  const first = hooks.close();
  assert.equal(hooks.close(), first);
  await first;
  const result = await work;
  assert.equal(result.diagnostics[0].phase, "observation");
  assert.equal(providerClosed, false);
  await assert.rejects(hooks.dispatch("tool.before", input()));
});

for (const early of ["unmatched", "invalid", "cancelled"])
  test(`owned unused source is cancelled on ${early} path without a read`, async () => {
    let reads = 0,
      cancels = 0;
    const source = new ContentSource(
      new ReadableStream(
        {
          pull() {
            reads++;
          },
          cancel() {
            cancels++;
          },
        },
        { highWaterMark: 0 },
      ),
    );
    const hooks = client({
      subscriptions: [
        {
          mode: "observe",
          events: ["session.end"],
          content: { default: "metadata" },
        },
      ],
      ...(early === "invalid" ? { capabilities: {} } : {}),
    });
    const value = { ...input(), native: { source } };
    const controller = new AbortController();
    if (early === "cancelled") controller.abort();
    try {
      if (early === "invalid")
        await assert.rejects(hooks.dispatch("tool.before", value));
      else
        await hooks.dispatch("tool.before", value, {
          signal: controller.signal,
        });
      assert.equal(reads, 0);
      assert.equal(cancels, 1);
    } finally {
      await hooks.close();
    }
  });

for (const [name, makeResponse, code] of [
  [
    "remote error",
    (init) =>
      Response.json({
        jsonrpc: "2.0",
        id: JSON.parse(init.body).id,
        error: {
          code: -32603,
          message: "SECRET endpoint detail",
          data: { token: "SECRET" },
        },
      }),
    "remote_rpc",
  ],
  [
    "malformed error",
    (init) =>
      Response.json({
        jsonrpc: "2.0",
        id: JSON.parse(init.body).id,
        error: { code: "bad", message: "SECRET" },
      }),
    "protocol_rejection",
  ],
  [
    "invalid JSON",
    () =>
      new Response("SECRET not JSON", {
        headers: { "content-type": "application/json" },
      }),
    "protocol_rejection",
  ],
  [
    "invalid effect",
    (init) => reply(init, [{ type: "unknown", token: "SECRET" }]),
    "protocol_rejection",
  ],
  [
    "transport",
    () => {
      throw new Error("SECRET network detail");
    },
    "transport",
  ],
])
  test(`typed diagnostics distinguish ${name} without leaking endpoint details`, async () => {
    const hooks = client({ fetch: async (_, init) => makeResponse(init) });
    try {
      const result = await hooks.dispatch("tool.before", input());
      assert.equal(result.diagnostics[0].code, code);
      assert.equal(result.diagnostics[0].phase, "interception");
      assert.equal(result.diagnostics[0].backendId, "test.operation");
      assert.equal(result.diagnostics[0].subscriptionIndex, 0);
      assert.equal(result.diagnostics[0].syntheticDenial, true);
      assert.equal(result.permission, "deny");
      assert.equal(
        JSON.stringify(result.diagnostics).includes("SECRET"),
        false,
      );
    } finally {
      await hooks.close();
    }
  });

test("outer budget stops selected content preparation before upload or publication", async () => {
  const entered = deferred();
  let cancelled = 0,
    sent = 0;
  const controller = new AbortController();
  const hooks = client({
    subscriptions: [
      {
        ...subscription,
        content: { default: "body" },
        upload: {
          endpoint: "https://example.test/upload",
          timeoutMs: 10000,
          maxBytes: 1024,
        },
      },
    ],
    fetch: async () => {
      sent++;
      throw new Error("unexpected delivery");
    },
  });
  const source = new ContentSource(
    new ReadableStream(
      {
        pull() {
          entered.resolve();
          return new Promise(() => {});
        },
        cancel() {
          cancelled++;
        },
      },
      { highWaterMark: 0 },
    ),
  );
  try {
    const work = hooks.dispatch(
      "tool.before",
      {
        ...input(),
        items: [
          { id: "body", kind: "text", mediaType: "text/plain", body: source },
        ],
      },
      { signal: controller.signal },
    );
    await entered.promise;
    controller.abort(new DOMException("outer budget", "TimeoutError"));
    const result = await work;
    assert.equal(result.interrupted, true);
    assert.equal(result.diagnostics[0].code, "deadline_exceeded");
    assert.equal(result.diagnostics[0].phase, "preparation");
    assert.equal(sent, 0);
    assert.equal(cancelled, 1);
  } finally {
    await hooks.close();
  }
});

test(
  "queued cancellation does not send, and active stdio cancellation reaps before return",
  { timeout: 10000 },
  async () => {
    const { mkdtemp, readFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = await mkdtemp(join(tmpdir(), "ahp-owned-child-"));
    const receipt = join(dir, "receipt.json");
    const source = `const fs=require('node:fs'); const child=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:['ignore',process.stdout,process.stderr]}); process.stdin.on('data', b=>fs.writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({pid:process.pid,descendant:child.pid,wire:b.toString()})));`;
    const hooks = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "test.child",
            transport: {
              type: "stdio",
              command: process.execPath,
              args: ["-e", source],
              lifecycle: "persistent",
            },
            subscriptions: [subscription],
          },
        ],
      },
      {
        source: "urn:test:reaping",
        capabilities: { "tool.before": { effects: [] } },
      },
    );
    const active = new AbortController(),
      queued = new AbortController();
    let descendant;
    try {
      const first = hooks.dispatch(
        "tool.before",
        { ...input(), id: "active" },
        { signal: active.signal },
      );
      let evidence;
      for (let i = 0; i < 500; i++) {
        try {
          evidence = JSON.parse(await readFile(receipt, "utf8"));
          break;
        } catch {}
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      assert.ok(evidence, "child accepted active request");
      descendant = evidence.descendant;
      const second = hooks.dispatch(
        "tool.before",
        { ...input(), id: "queued" },
        { signal: queued.signal },
      );
      queued.abort(new DOMException("queue deadline", "TimeoutError"));
      const queuedResult = await second;
      assert.equal(queuedResult.interrupted, true);
      assert.equal(JSON.parse(evidence.wire).id, "active");
      active.abort();
      const result = await first;
      assert.equal(result.interrupted, true);
      assert.throws(() => process.kill(evidence.pid, 0), { code: "ESRCH" });
      assert.equal(
        JSON.parse(JSON.parse(await readFile(receipt, "utf8")).wire).id,
        "active",
      );
    } finally {
      active.abort();
      queued.abort();
      await hooks.close();
      // The fixture owns its descendant; Hooks owns only its directly spawned child.
      if (descendant) {
        try {
          process.kill(descendant, "SIGKILL");
        } catch {}
      }
      await rm(dir, { recursive: true, force: true });
    }
  },
);
