// @ts-check
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createServer } from "node:http";
import { once } from "node:events";
import { effectiveEvent } from "./settlement.mjs";
import { TaskLineage } from "./task-lineage.mjs";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
/** @type {typeof import("@agenthooksprotocol/sdk/client")} */
const { Hooks, auth, composeResponse } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);
/** @type {typeof import("@agenthooksprotocol/sdk/server")} */
const { hooks } = await import(
  require.resolve("@agenthooksprotocol/sdk/server")
);

// The application owns HTTP and authorization; the public SDK owns wire framing,
// routing, validation, composition and observer scheduling.
/**
 * @param {import("node:test").TestContext} t
 * @param {{id: string, mode: "intercept" | "observe", events: import("@agenthooksprotocol/sdk/client").EventType[]}[]} routes
 * @param {import("@agenthooksprotocol/sdk/client").EventCapabilities} capabilities
 * @param {(message: import("@agenthooksprotocol/sdk/server").Message, route: string) => ReturnType<import("@agenthooksprotocol/sdk/server").Handler>} handler
 * @param {string} source
 */
async function receiver(
  t,
  routes,
  capabilities,
  handler,
  source = "urn:test:settlement",
) {
  const server = createServer(async (req, res) => {
    try {
      assert.equal(req.headers.authorization, "Bearer settlement-token");
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const response = await hooks.handle(
        new Request(`http://localhost${req.url}`, {
          method: req.method,
          headers: {
            "content-type": req.headers["content-type"] ?? "application/json",
          },
          body: Buffer.concat(chunks),
        }),
        (message) => handler(message, req.url),
      );
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      res.writeHead(500);
      res.end(String(error));
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: routes.map(({ id, mode, events }) => ({
        id: `test.${id}`,
        transport: {
          type: "http",
          url: `http://127.0.0.1:${address.port}/${id}`,
        },
        subscriptions: [
          {
            mode,
            events,
            content: { default: "metadata" },
            ...(mode === "intercept"
              ? { timeoutMs: 1000, failurePolicy: "fail-closed" }
              : {}),
          },
        ],
      })),
    },
    {
      source,
      capabilities,
      auth: auth({
        authenticate: async (context, options) =>
          context.purpose === "upload"
            ? auth.authenticate(context, options)
            : { token: "settlement-token" },
      }),
    },
  );
  t.after(async () => {
    await client.close();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  return client;
}
/** @satisfies {import("@agenthooksprotocol/sdk/client").BoundaryInput<"tool.before">} */
const toolInput = {
  id: "same",
  call: { id: "call" },
  path: "native",
  tool: { name: "read_file", origin: "native", input: { x: 1 } },
};

test("effective observation payload and offline composition use public SDK responses", async (t) => {
  /** @type {import("@agenthooksprotocol/sdk/server").InterceptRequest | undefined} */
  let request;
  /** @satisfies {import("@agenthooksprotocol/sdk/client").Capabilities} */
  const capabilities = {
    effects: ["modify"],
    modify: { input: { replace: true, merge: false } },
  };
  const client = await receiver(
    t,
    [{ id: "policy", mode: "intercept", events: ["tool.before"] }],
    { "tool.before": capabilities },
    (message) => {
      assert.equal(message.method, "hooks/intercept");
      if (message.method !== "hooks/intercept")
        throw Error("Expected interception");
      request = message;
      return {
        effects: [
          {
            type: "modify",
            target: "input",
            operation: "replace",
            value: { x: 2 },
          },
        ],
      };
    },
  );
  const result = await client.dispatch("tool.before", toolInput);
  assert.deepEqual(result.errors, []);
  await result.observations;
  assert.equal(result.event.tool.input.x, 2);
  assert.equal(toolInput.tool.input.x, 1);
  // Offline composition consumes the canonical public client response, not an
  // interop evaluator or a hand-built positive response envelope.
  const reply = result.response;
  assert.ok(request);
  const offline = composeResponse(
    request.params.event,
    [],
    reply,
    capabilities,
  );
  assert.deepEqual(offline.event, result.event);
  assert.deepEqual(
    effectiveEvent(request.params.event, { input: result.event.tool.input }),
    result.event,
  );
});

// Explicit malformed-input bypass: impossible lineage must remain constructible
// independently of SDK validation so the receiving application's guard is tested.
const malformedWire = (
  id,
  type,
  parentEventId,
  task = { id: "task", operation: "update", change: { status: "done" } },
) => ({
  params: { event: { id, source: "urn:source", type, parentEventId, task } },
});
test("task lineage receives canonical SDK events and rejects malformed explicit bypasses", async (t) => {
  const lineage = new TaskLineage();
  const messages = [];
  const client = await receiver(
    t,
    [
      {
        id: "lineage",
        mode: "observe",
        events: ["task.change.before", "task.change.after"],
      },
    ],
    {
      "task.change.before": { modes: ["observe"] },
      "task.change.after": { modes: ["observe"] },
    },
    (message) => {
      messages.push(message);
      lineage.accept(message);
    },
    "urn:source",
  );
  /** @satisfies {import("@agenthooksprotocol/sdk/client").BoundaryInput<"task.change.before">["task"]} */
  const task = { id: "task", operation: "update", change: { status: "done" } };
  /** @type {["task.change.after" | "task.change.before", string, string][]} */
  const occurrences = [
    ["task.change.after", "after", "before"],
    ["task.change.before", "before", "tool"],
  ];
  for (const [type, id, parentEventId] of occurrences) {
    const result = await client.dispatch(type, { id, parentEventId, task });
    assert.deepEqual(result.errors, []);
    assert.deepEqual(await result.observations, []);
  }
  assert.equal(messages.length, 2);
  assert.throws(() =>
    lineage.accept(malformedWire("tool", "tool.before", "after")),
  );
  const mismatch = new TaskLineage();
  mismatch.accept(messages[0]);
  assert.throws(() =>
    mismatch.accept(
      malformedWire("before", "task.change.before", undefined, {
        ...task,
        id: "wrong",
      }),
    ),
  );
  assert.throws(() =>
    lineage.accept(
      malformedWire("noop", "task.change.after", undefined, {
        ...task,
        prior: { status: "done" },
      }),
    ),
  );
  assert.throws(() =>
    new TaskLineage({ requireKnownParents: true }).accept(
      malformedWire("child", "task.change.after", "absent"),
    ),
  );
  const other = await receiver(
    t,
    [{ id: "other", mode: "observe", events: ["task.change.before"] }],
    { "task.change.before": { modes: ["observe"] } },
    (message) => lineage.accept(message),
    "urn:other",
  );
  assert.deepEqual(
    await (
      await other.dispatch("task.change.before", { id: "before", task })
    ).observations,
    [],
  );
});

test("typed task/workspace controls use public SDK and reject malformed offline bypasses", async (t) => {
  /** @type {import("@agenthooksprotocol/sdk/client").Effect[]} */
  let effects = [{ type: "deny", reason: "policy" }];
  /** @type {import("@agenthooksprotocol/sdk/server").InterceptRequest | undefined} */
  let request;
  const client = await receiver(
    t,
    [
      {
        id: "policy",
        mode: "intercept",
        events: ["task.change.before", "workspace.change.before"],
      },
    ],
    {
      "task.change.before": { effects: ["deny"] },
      "workspace.change.before": {
        effects: ["modify", "deny"],
        modify: { workspace: { replace: true, merge: true } },
      },
    },
    (message) => {
      if (message.method !== "hooks/intercept")
        throw Error("Expected interception");
      request = message;
      return { effects };
    },
  );
  const task = await client.dispatch("task.change.before", {
    id: "task-before",
    task: {
      id: "durable-task",
      operation: "update",
      change: { status: "native-done" },
    },
  });
  assert.deepEqual(task.errors, []);
  assert.equal(task.response.result.effects[0].type, "deny");
  assert.ok(request);
  /** @param {import("@agenthooksprotocol/sdk/client").Effect} effect
   * @returns {import("@agenthooksprotocol/sdk/client").InterceptResponse} */
  const bypass = (effect) => ({
    jsonrpc: "2.0",
    id: request.id,
    result: { protocolVersion: "draft", effects: [effect] },
  });
  assert.throws(() =>
    composeResponse(
      request.params.event,
      [],
      bypass({ type: "allow" }),
      request.params.capabilities,
    ),
  );
  effects = [
    {
      type: "modify",
      target: "workspace",
      operation: "replace",
      value: { cwd: "/new" },
    },
  ];
  /** @satisfies {import("@agenthooksprotocol/sdk/client").BoundaryInput<"workspace.change.before">} */
  const input = {
    id: "workspace-before",
    workspace: { kind: "cwd", change: { cwd: "/old" } },
  };
  const modified = await client.dispatch("workspace.change.before", input);
  assert.deepEqual(modified.errors, []);
  assert.equal(modified.event.workspace.change.cwd, "/new");
  // Deliberately bypass hooks.handle, which would reject an unsupported effect.
  assert.throws(() =>
    composeResponse(
      request.params.event,
      [],
      bypass({
        type: "modify",
        target: "workspace",
        operation: "replace",
        value: null,
      }),
      request.params.capabilities,
    ),
  );
  effects = [{ type: "deny", reason: "policy" }];
  const denied = await client.dispatch("workspace.change.before", {
    ...input,
    id: "workspace-denied",
  });
  assert.deepEqual(denied.errors, []);
  assert.equal(denied.response.result.effects[0].type, "deny");
});

test("short-circuit downgrades only uncalled interceptors and awaits observers", async (t) => {
  const received = [];
  let release = () => {};
  const blocked = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  t.after(release);
  const client = await receiver(
    t,
    [
      { id: "called", mode: "intercept", events: ["tool.before"] },
      { id: "remaining", mode: "intercept", events: ["tool.before"] },
      { id: "explicit", mode: "observe", events: ["tool.before"] },
    ],
    {
      "tool.before": {
        modes: ["intercept", "observe"],
        capabilities: {
          effects: ["modify", "deny"],
          modify: { input: { replace: true, merge: false } },
        },
      },
    },
    async (message, route) => {
      received.push({ message, route });
      if (message.method === "hooks/intercept")
        return {
          effects: [
            {
              type: "modify",
              target: "input",
              operation: "replace",
              value: { x: 2 },
            },
            { type: "deny", reason: "policy" },
          ],
        };
      await blocked;
    },
  );
  let settled = false;
  const work = client.dispatch("tool.before", toolInput).then((result) => {
    settled = true;
    return result;
  });
  // Both observation callbacks must start, but the boundary must remain pending
  // until their processing completes.
  const deadline = Date.now() + 1000;
  while (received.length < 3 && Date.now() < deadline)
    await new Promise((resolve) => setTimeout(resolve, 5));
  assert.equal(settled, false);
  assert.deepEqual(
    received
      .filter((x) => x.message.method === "hooks/intercept")
      .map((x) => x.route),
    ["/called"],
  );
  const notes = received.filter((x) => x.message.method === "hooks/observe");
  assert.deepEqual(notes.map((x) => x.route).sort(), [
    "/explicit",
    "/remaining",
  ]);
  for (const { message: note } of notes) {
    assert.equal(note.params.event.id, "same");
    assert.equal(note.params.event.tool.input.x, 2);
    assert.deepEqual(Object.keys(note.params).sort(), [
      "event",
      "protocolVersion",
    ]);
    assert.equal(Object.hasOwn(note, "id"), false);
  }
  release();
  const result = await work;
  assert.equal(settled, true);
  assert.deepEqual(result.errors, []);
  assert.equal(result.event.tool.input.x, 2);
  assert.deepEqual(await result.observations, []);
});

test("chain refreshes receiver evidence after a fast final interception", async (t) => {
  const { runChain } = await import("./observation-chain.mjs");
  /** @type {{kind: string, id: string}[]} */
  const entries = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const reply = await hooks.handle(
      new Request("http://localhost/hooks", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: Buffer.concat(chunks),
      }),
      (message) => {
        assert.notEqual(message.method, "hooks/capabilities");
        if (message.method === "hooks/capabilities")
          throw Error("Unexpected discovery");
        if (message.method === "hooks/intercept") {
          assert.equal(message.params.state?.permission, "none");
          assert.equal(message.params.state?.candidate, null);
        }
        entries.push({
          kind: message.method === "hooks/intercept" ? "received" : "observed",
          id: message.params.event.id,
        });
        return message.method === "hooks/intercept"
          ? { effects: [] }
          : undefined;
      },
    );
    res
      .writeHead(reply.status, Object.fromEntries(reply.headers))
      .end(await reply.text());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  let polls = 0;
  const result = await runChain(
    {
      id: "fast-chain",
      requests: {
        a: {
          params: {
            event: {
              ...toolInput,
              id: "fast-chain",
              type: "tool.before",
              source: "urn:test:chain",
              time: "2026-01-01T00:00:00Z",
            },
            capabilities: { effects: [] },
            state: { permission: "none", candidate: null },
          },
        },
      },
      chain: {
        subscriptions: [
          {
            id: "policy",
            mode: "intercept",
            content: "metadata",
            failurePolicy: "fail-open",
          },
          {
            id: "audit",
            mode: "observe",
            content: "metadata",
            failurePolicy: "fail-open",
          },
        ],
      },
    },
    {
      transport: {
        type: "http",
        url: `http://127.0.0.1:${address.port}/hooks`,
      },
      control: async (path, value) => {
        if (path === "/receipts") {
          if (++polls === 1) {
            // Snapshot before receipt, delivered only after the boundary settles.
            while (!entries.some((entry) => entry.kind === "observed"))
              await new Promise((resolve) => setTimeout(resolve, 1));
            return { entries: [] };
          }
          return { entries };
        }
        if (path === "/wait-observed")
          assert.deepEqual(value, { eventId: "fast-chain", count: 1 });
      },
    },
  );
  assert.deepEqual(result.called, ["policy"]);
  assert.deepEqual(result.observations, ["audit"]);
  assert.equal(polls, 2);
});
