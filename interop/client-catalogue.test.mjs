import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks, BackendTransport } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);
const serverModule = require.resolve("@agenthooksprotocol/sdk/server");
const { hooks: serverHooks } = await import(serverModule);
const { draftCodecs } = await import(
  require.resolve("@agenthooksprotocol/sdk/draft")
);

// Independent minimal canonical occurrences: no interop evaluator or SDK implementation fixtures.
const tool = {
  call: { id: "call" },
  path: "native",
  tool: { name: "read_file", origin: "native", input: {} },
};
const model = { id: "model", provider: "provider" };
const attempt = { id: "attempt", number: 1 };
const execution = { status: "executed" };
const item = {
  id: "item",
  kind: "message",
  mediaType: "text/plain",
  selection: "metadata",
  role: "assistant",
};
const change = {
  scope: "user",
  source: "settings",
  settings: [],
  summary: "settings updated",
};
const task = { id: "task", operation: "create", change: { status: "open" } };
const workspace = { kind: "cwd", change: { cwd: "/workspace" } };
const occurrences = {
  "tool.before": tool,
  "tool.after": { ...tool, outcome: "ok", execution, items: [] },
  "session.start": {
    session: { id: "session" },
    harness: { name: "test", version: "1" },
    permissionMode: "default",
    trigger: "startup",
    items: [],
  },
  "session.end": {
    session: { id: "session" },
    outcome: "completed",
    reason: "finished",
  },
  "config.change.before": { change },
  "config.change.after": { change },
  "turn.start": { turn: { id: "turn" }, trigger: "user", items: [] },
  "turn.finish.before": {
    turn: { id: "turn" },
    outcome: "completed",
    continuationCount: 0,
    items: [],
  },
  "turn.end": {
    turn: { id: "turn" },
    outcome: "completed",
    continuationCount: 0,
    items: [],
  },
  "turn.progress": {
    turn: { id: "turn" },
    item: { id: "item" },
    delta: item,
    final: false,
  },
  "model.request.before": { model, attempt, params: {}, items: [] },
  "model.response.after": {
    model,
    attempt,
    execution,
    items: [],
    finishReason: "stop",
  },
  "model.error": {
    model,
    attempt,
    execution,
    error: { message: "failed", class: "provider" },
  },
  "model.switch.before": {
    current: model,
    proposed: model,
    reason: "requested",
  },
  "model.switch.after": {
    previous: model,
    current: model,
    reason: "requested",
  },
  "tool.permission.request": { ...tool, suggestions: [], sandboxBypass: false },
  "tool.permission.resolved": { ...tool, decision: "allow", decidedBy: "user" },
  "tool.progress": {
    ...tool,
    partialOutput: { ...item, kind: "tool_result", role: "tool" },
    backgrounded: false,
  },
  "tool.batch.after": {
    batch: { id: "batch" },
    calls: [{ ...tool, outcome: "ok", execution }],
  },
  "context.compact.before": { trigger: "auto", items: [] },
  "context.compact.after": {
    summary: { ...item, role: "system" },
    removed: [],
    execution,
  },
  "task.change.before": { task },
  "task.change.after": { task },
  "user.attention": {
    attention: { kind: "notification", title: [], message: [] },
  },
  "user.elicitation.request": { elicitation: { mode: "form", server: "test" } },
  "user.elicitation.result": {
    elicitation: { mode: "form", server: "test", action: "decline" },
  },
  "user.message.inbound": {
    message: { channel: "chat", sender: "user", text: [] },
  },
  "user.message.outbound": { message: { channel: "chat", payload: [] } },
  "workspace.change.before": { workspace },
  "workspace.change.after": { workspace },
  "file.changed": {
    changes: [
      { path: "/workspace/file", operation: "update", agentCaused: true },
    ],
  },
  "hook.failure": {
    parentEventId: "parent",
    failure: {
      backendId: "test.policy",
      policy: "fail-open",
      reason: "unavailable",
    },
  },
};
const methodFor = (type) =>
  type.replace(/\.([a-z])/g, (_, letter) => letter.toUpperCase());
const observe = (includeNative) => ({
  mode: "observe",
  events: ["*"],
  content: { default: "metadata" },
  includeNative,
});
const options = {
  source: "urn:test:catalogue",
  capabilities: Object.fromEntries(
    Object.keys(occurrences).map((event) => [event, { modes: ["observe"] }]),
  ),
};
async function until(predicate) {
  for (let i = 0; i < 300; i++) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail("Timed out waiting for background observations");
}
async function receiver() {
  const messages = [];
  const server = createServer(async (req, res) => {
    let text = "";
    for await (const chunk of req) text += chunk;
    const response = await serverHooks.handle(
      new Request("http://receiver.test/hooks", {
        method: "POST",
        headers: req.headers,
        body: text,
      }),
      (message) => {
        // Compare wire data without the parser's null-prototype objects.
        messages.push(structuredClone(message));
      },
    );
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(new Uint8Array(await response.arrayBuffer()));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    messages,
    url: `http://127.0.0.1:${server.address().port}/hooks`,
    close: () =>
      new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections();
      }),
  };
}
const registration = (transport, subscriptions) => ({
  protocolVersion: "draft",
  hooks: [{ id: "test.catalogue", transport, subscriptions }],
});

test(
  "all 32 public boundaries emit canonical observations with opt-in native data",
  { timeout: 15000 },
  async () => {
    const server = await receiver();
    const hooks = new Hooks(
      registration({ type: "http", url: server.url }, [
        observe(true),
        observe(false),
      ]),
      options,
    );
    const results = new Map();
    try {
      await hooks.initialized;
      assert.equal(
        server.messages.length,
        0,
        "initialization advertises capabilities without a backend handshake",
      );
      assert.equal(Object.keys(occurrences).length, 32);
      for (const [type, payload] of Object.entries(occurrences)) {
        const input = structuredClone({
          ...payload,
          native: { type: "host.event", details: { event: type } },
        });
        const original = structuredClone(input);
        const result = await hooks
          .dispatch(type, input)
          .catch((error) => assert.fail(`${type}: ${error.message}`));
        assert.equal(result.event.type, type);
        assert.equal(result.event.source, options.source);
        assert.ok(result.event.id);
        assert.ok(Number.isFinite(Date.parse(result.event.time)));
        assert.deepEqual(result.response.result.effects, []);
        assert.deepEqual(result.errors, []);
        assert.equal(result.interrupted, false);
        assert.deepEqual(
          input,
          original,
          "boundary must not mutate producer input",
        );
        results.set(type, result);
      }
      await until(() => server.messages.length === 64);
      assert.equal(
        new Set([...results.values()].map((result) => result.event.id)).size,
        32,
      );
      for (const message of server.messages) {
        assert.equal(message.method, "hooks/observe");
        assert.equal(message.id, undefined);
        assert.equal(message.params.protocolVersion, "draft");
        assert.doesNotThrow(() =>
          draftCodecs.parseObserveNotification(message),
        );
      }
      for (const [type, result] of results) {
        const pair = server.messages
          .filter((message) => message.params.event.type === type)
          .map((message) => message.params.event);
        assert.equal(pair.length, 2, type);
        assert.equal(pair.filter((event) => "native" in event).length, 1, type);
        for (const event of pair) {
          assert.equal(event.id, result.event.id);
          assert.equal(event.time, result.event.time);
          if ("native" in event)
            assert.deepEqual(event.native, result.event.native);
          const projected = structuredClone(result.event);
          if (!("native" in event)) delete projected.native;
          assert.deepEqual(event, projected, type);
        }
      }
      const manifest = results.get("session.start").event.manifest;
      assert.deepEqual(
        manifest.events.map((entry) => entry.event).sort(),
        Object.keys(occurrences).sort(),
      );
      const advertised = new Hooks(
        registration({ type: "http", url: server.url }, [observe(false)]),
        { ...options, capabilities: manifest },
      );
      try {
        const started = await advertised.dispatch(
          "session.start",
          occurrences["session.start"],
        );
        assert.deepEqual(
          started.event.manifest,
          manifest,
          "explicit static manifests are injected unchanged",
        );
        await until(() => server.messages.length === 65);
      } finally {
        await advertised.close();
      }
    } finally {
      await hooks.close();
      await server.close();
    }
  },
);

for (const lifecycle of ["persistent", "per_event"]) {
  test(
    `public Hooks owns ${lifecycle} stdio interception and observation lifecycle`,
    // Per-event children each load and compile the real receiver schemas.
    { timeout: 30000 },
    async () => {
      const directory = await mkdtemp(join(tmpdir(), "ahp-hooks-stdio-"));
      const path = join(directory, "messages.jsonl");
      const script = `const fs=require('node:fs');const readline=require('node:readline');
      const server=import(require('node:url').pathToFileURL(process.argv[2]).href);
      readline.createInterface({input:process.stdin}).on('line',async line=>{
        const m=JSON.parse(line);fs.appendFileSync(process.argv[1],JSON.stringify({pid:process.pid,message:m})+'\\n');
        const {hooks}=await server;
        const response=await hooks.handle(new Request('http://receiver.test/hooks',{method:'POST',headers:{'content-type':'application/json'},body:line}),()=>({effects:[{type:'message',text:'accepted'}]}));
        const body=await response.text();if(body) console.log(body);
      });`;
      const config = registration(
        {
          type: "stdio",
          lifecycle,
          command: process.execPath,
          args: ["-e", script, path, serverModule],
        },
        [
          {
            mode: "intercept",
            events: ["tool.before"],
            timeoutMs: 10000,
            failurePolicy: "fail-closed",
            content: { default: "metadata" },
          },
          observe(true),
        ],
      );
      const hooks = new Hooks(config, {
        ...options,
        capabilities: {
          "tool.before": {
            modes: ["intercept", "observe"],
            capabilities: { effects: ["message"] },
          },
        },
      });
      const rows = async () =>
        (await readFile(path, "utf8")).trim().split("\n").map(JSON.parse);
      try {
        await hooks.initialized;
        await assert.rejects(readFile(path), { code: "ENOENT" });
        const one = await hooks.dispatch("tool.before", structuredClone(tool));
        const two = await hooks.dispatch("tool.before", structuredClone(tool));
        for (const result of [one, two]) {
          assert.deepEqual(result.errors, []);
          assert.deepEqual(result.response.result.effects, [
            { type: "message", text: "accepted" },
          ]);
        }
        await until(async () => (await rows()).length === 4);
        const messages = await rows();
        assert.equal(
          messages.filter((row) => row.message.method === "hooks/intercept")
            .length,
          2,
        );
        assert.equal(
          messages.filter((row) => row.message.method === "hooks/observe")
            .length,
          2,
        );
        assert.ok(
          messages.every((row) =>
            ["hooks/intercept", "hooks/observe"].includes(row.message.method),
          ),
        );
        const pids = new Set(messages.map((row) => row.pid));
        assert.equal(pids.size, lifecycle === "persistent" ? 1 : 4);
        await hooks.close();
        for (const pid of pids)
          assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
        await hooks.close();
      } finally {
        await hooks.close();
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
}

test(
  "public consumer declarations compile with positive and negative boundary inputs",
  { timeout: 30000 },
  () => {
    const root = fileURLToPath(new URL("..", import.meta.url));
    const compiler = require.resolve("typescript/bin/tsc");
    const result = spawnSync(
      process.execPath,
      [
        compiler,
        "--noEmit",
        "--strict",
        "--exactOptionalPropertyTypes",
        "--noUncheckedIndexedAccess",
        "--target",
        "ES2022",
        "--module",
        "NodeNext",
        "--moduleResolution",
        "NodeNext",
        "--lib",
        "ES2022,DOM",
        "--skipLibCheck",
        "packages/sdk/test/client-types.ts",
        "packages/sdk/test/client-example.ts",
        "node-shims.d.ts",
      ],
      { cwd: root, encoding: "utf8", timeout: 25000 },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  },
);

test("late authenticated fetch responses are cancelled after transport close", async () => {
  let deliver;
  let cancelled = false;
  const body = new ReadableStream({
    cancel() {
      cancelled = true;
    },
  });
  const transport = new BackendTransport(
    {
      id: "test.late",
      subscriptions: [],
      transport: { type: "http", url: "https://backend.test" },
    },
    () =>
      new Promise((resolve) => {
        deliver = resolve;
      }),
  );
  const rejected = assert.rejects(
    transport.request({
      jsonrpc: "2.0",
      id: 1,
      method: "hooks/capabilities",
      params: {},
    }),
  );
  await transport.close();
  await rejected;
  deliver(
    new Response(body, { headers: { "content-type": "application/json" } }),
  );
  await until(() => cancelled);
  assert.equal(body.locked, false);
});

// Public transport regression checks: ignored fetch cancellation must not retain response streams.
test(
  "HTTP transport cancels rejected, oversized, and interrupted response bodies",
  { timeout: 5000 },
  async () => {
    for (const scenario of [
      "status",
      "media",
      "oversize",
      "abort",
      "close",
      "notification",
    ]) {
      let cancelled = false;
      const body = new ReadableStream({
        start(controller) {
          if (scenario === "oversize")
            controller.enqueue(new Uint8Array(1024 * 1024 + 1));
          if (scenario === "notification")
            controller.enqueue(new Uint8Array([32]));
        },
        cancel() {
          cancelled = true;
        },
      });
      const transport = new BackendTransport(
        {
          id: "test.http",
          subscriptions: [],
          transport: { type: "http", url: "https://backend.test" },
        },
        async () =>
          new Response(body, {
            status:
              scenario === "status"
                ? 500
                : scenario === "notification"
                  ? 202
                  : 200,
            headers: {
              "content-type":
                scenario === "media" ? "text/plain" : "application/json",
            },
          }),
      );
      const controller = new AbortController();
      try {
        const pending =
          scenario === "notification"
            ? transport.notify(
                { jsonrpc: "2.0", method: "hooks/observe", params: {} },
                controller.signal,
              )
            : transport.request(
                {
                  jsonrpc: "2.0",
                  id: 1,
                  method: "hooks/capabilities",
                  params: {},
                },
                controller.signal,
              );
        const rejected = assert.rejects(pending);
        if (scenario === "abort" || scenario === "close") {
          await new Promise((resolve) => setImmediate(resolve));
          if (scenario === "close") await transport.close();
          else controller.abort();
        }
        await rejected;
        await until(() => cancelled);
        assert.equal(body.locked, false);
      } finally {
        await transport.close();
      }
    }
  },
);
