import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { hooks } = await import(
  require.resolve("@agenthooksprotocol/sdk/server")
);
const request = (message) =>
  new Request("https://receiver.test/hooks", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(message),
  });
const capabilities = () => ({
  effects: ["deny", "modify", "inject", "flow"],
  modify: { input: { replace: true, merge: false } },
  inject: { context: { append: true, deliverAt: ["now"] } },
  flow: { operations: ["stop"] },
});
const intercept = () => ({
  jsonrpc: "2.0",
  id: "e",
  method: "hooks/intercept",
  params: {
    protocolVersion: "draft",
    capabilities: capabilities(),
    event: {
      id: "e",
      source: "urn:test",
      time: "2026-01-01T00:00:00Z",
      type: "tool.before",
      call: { id: "c" },
      path: "native",
      tool: { name: "read", origin: "native", input: { path: "a" } },
    },
  },
});
const observe = () => {
  const m = intercept();
  delete m.id;
  m.method = "hooks/observe";
  delete m.params.capabilities;
  return m;
};
const manifest = {
  authentication: [],
  contentCategories: [],
  correlationIdentityFields: [],
  events: [],
  gaps: [],
  limits: {},
  managedPolicy: { disableable: true, scopes: [] },
  toolPaths: [],
  transports: ["http"],
};

test("server handle supplies canonical correlation and version to synchronous policy results", async () => {
  const response = await hooks.handle(request(intercept()), (message) => {
    assert.equal(message.method, "hooks/intercept");
    assert.equal(message.params.event.tool.input.path, "a");
    return { effects: [{ type: "deny", reason: "policy" }] };
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.deepEqual(await response.json(), {
    jsonrpc: "2.0",
    id: "e",
    result: {
      protocolVersion: "draft",
      effects: [{ type: "deny", reason: "policy" }],
    },
  });
});

test("server accepts complete supported compound without applying it to host state", async () => {
  const effects = [
    {
      type: "modify",
      target: "input",
      operation: "replace",
      value: { path: "b" },
    },
    {
      type: "inject",
      target: "context",
      operation: "append",
      deliverAt: "now",
      value: "context",
    },
    { type: "flow", operation: "stop", reason: "done" },
  ];
  const response = await hooks.handle(request(intercept()), async () => ({
    effects,
  }));
  const body = await response.json();
  assert.deepEqual(body.result?.effects, effects, JSON.stringify(body));
});

test("canonical capabilities method uses the same callback and endpoint", async () => {
  const response = await hooks.handle(
    request({
      jsonrpc: "2.0",
      id: "caps",
      method: "hooks/capabilities",
      params: { protocolVersion: "draft" },
    }),
    (message) => {
      assert.equal(message.method, "hooks/capabilities");
      return { manifest };
    },
  );
  assert.deepEqual(await response.json(), {
    jsonrpc: "2.0",
    id: "caps",
    result: { protocolVersion: "draft", manifest },
  });
});

test("observe accepts void and never returns a JSON-RPC body including callback failures", async () => {
  for (const handler of [
    () => {},
    async () => {},
    () => {
      throw new Error("Bearer SECRET");
    },
    () => ({ effects: [] }),
  ]) {
    const response = await hooks.handle(request(observe()), handler);
    assert.ok([204, 500].includes(response.status));
    assert.equal(await response.text(), "");
  }
  const invalid = observe();
  invalid.params.event.time = "invalid";
  const response = await hooks.handle(request(invalid), () => {
    assert.fail("must not call");
  });
  assert.equal(response.status, 400);
  assert.equal(await response.text(), "");
});

for (const effect of [
  { type: "future" },
  { type: "deny" },
  { type: "allow" },
  { type: "modify", target: "input", operation: "merge", value: {} },
  { type: "modify", target: "output", operation: "replace", value: {} },
  {
    type: "inject",
    target: "context",
    operation: "append",
    deliverAt: "next_turn",
    value: "x",
  },
  { type: "flow", operation: "continue" },
])
  test(`atomic rejection of invalid/unsupported effect ${JSON.stringify(effect)}`, async () => {
    const response = await hooks.handle(request(intercept()), () => ({
      effects: [{ type: "deny", reason: "valid" }, effect],
    }));
    const body = await response.json();
    assert.equal(body.error?.code, -32004);
    assert.equal(body.result, undefined);
  });

test("incoming canonical schema validation prevents invoking policy and mutation cannot broaden support", async () => {
  for (const mutate of [
    (m) => (m.id = "wrong"),
    (m) => (m.params.event.time = "bad"),
    (m) => (m.params.capabilities.modify.output = { replace: true }),
  ]) {
    const m = intercept();
    mutate(m);
    const result = await hooks.handle(request(m), () =>
      assert.fail("invalid input invoked handler"),
    );
    assert.equal((await result.json()).error.code, -32602);
  }
  const result = await hooks.handle(request(intercept()), (m) => {
    m.id = "changed";
    m.params.capabilities.effects.push("allow");
    return { effects: [{ type: "allow" }] };
  });
  assert.deepEqual(await result.json(), {
    jsonrpc: "2.0",
    id: "e",
    error: { code: -32004, message: "Backend internal error" },
  });
});

test("JSON-RPC parse, batch, method, version and HTTP framing failures are safe", async () => {
  const bad = new Request("https://receiver.test", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{Bearer SECRET",
  });
  const parse = await hooks.handle(bad, () => assert.fail());
  assert.equal(parse.status, 400);
  assert.equal((await parse.json()).error.code, -32700);
  for (const [message, code] of [
    [[], -32600],
    [{ jsonrpc: "2.0", id: "x", method: "other" }, -32601],
    [{ ...intercept(), params: { protocolVersion: "wrong" } }, -32001],
  ]) {
    const response = await hooks.handle(request(message), () => assert.fail());
    assert.equal((await response.json()).error.code, code);
  }
  const unknown = await hooks.handle(
    request({ jsonrpc: "2.0", method: "other" }),
    () => assert.fail(),
  );
  assert.equal(await unknown.text(), "");
  assert.equal(
    (
      await hooks.handle(new Request("https://receiver.test"), () =>
        assert.fail(),
      )
    ).status,
    405,
  );
  assert.equal(
    (
      await hooks.handle(
        new Request("https://receiver.test", { method: "POST", body: "{}" }),
        () => assert.fail(),
      )
    ).status,
    415,
  );
  const exception = await hooks.handle(request(intercept()), async () => {
    throw new Error("https://user:password@host Bearer SECRET");
  });
  assert.deepEqual(await exception.json(), {
    jsonrpc: "2.0",
    id: "e",
    error: { code: -32004, message: "Backend internal error" },
  });
});

test(
  "public server consumer compiles with exact optional properties",
  { timeout: 30000 },
  () => {
    const result = spawnSync(
      process.execPath,
      [
        require.resolve("typescript/bin/tsc"),
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
        "packages/sdk/test/server-types.ts",
        "node-shims.d.ts",
      ],
      {
        cwd: fileURLToPath(new URL("..", import.meta.url)),
        encoding: "utf8",
        timeout: 25000,
      },
    );
    assert.equal(result.status, 0, result.stdout + result.stderr);
  },
);

test("whole callback results reject atomically, including malformed and non-JSON compounds", async () => {
  const cycle = {};
  cycle.self = cycle;
  for (const result of [
    undefined,
    null,
    [],
    { effects: [], protocolVersion: "draft" },
    { effects: [{ type: "deny", reason: "valid" }], manifest: {} },
    {
      effects: [
        { type: "modify", target: "input", operation: "replace", value: cycle },
      ],
    },
    {
      effects: [
        {
          type: "modify",
          target: "input",
          operation: "replace",
          value: { bad: undefined },
        },
      ],
    },
  ]) {
    const response = await hooks.handle(request(intercept()), () => result);
    const body = await response.json();
    assert.equal(body.error?.code, -32004, JSON.stringify(body));
    assert.equal(body.result, undefined);
  }
});

test("canonical capabilities callback result validation rejects malformed manifests", async () => {
  const response = await hooks.handle(
    request({
      jsonrpc: "2.0",
      id: "caps",
      method: "hooks/capabilities",
      params: { protocolVersion: "draft" },
    }),
    () => ({ manifest: {} }),
  );
  assert.equal((await response.json()).error.code, -32004);
});

// Build bounded wire text directly: JSON.stringify itself has a runtime-specific
// recursion limit, which must not prevent these requests from reaching handle.
for (const depth of [32, 512, 1500, 2500, 5000, 10000]) {
  for (const notification of [false, true]) {
    for (const malformed of [false, true]) {
      test(`deep external JSON: depth=${depth}, notification=${notification}, malformed=${malformed}`, async () => {
        const message = notification ? observe() : intercept();
        message.params.event.tool.input = "NESTED_INPUT";
        if (malformed) message.params.event.tool.name = 42;
        const nested =
          '{"x":'.repeat(depth) + '"Bearer SECRET"' + "}".repeat(depth);
        const body = JSON.stringify(message).replace('"NESTED_INPUT"', nested);
        assert.ok(body.length < 65000, "keep adversarial input bounded");
        let called = false;
        const response = await hooks.handle(
          new Request("https://receiver.test/hooks", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
          }),
          () => {
            called = true;
            return notification ? undefined : { effects: [] };
          },
        );
        assert.ok(response instanceof Response);
        if (malformed) assert.equal(called, false);
        if (!malformed && depth === 32) assert.equal(called, true);
        if (notification) {
          assert.equal(await response.text(), "");
          if (called) assert.equal(response.status, 204);
          else assert.ok([400, 500].includes(response.status));
        } else {
          assert.equal(response.status, 200);
          const reply = await response.json();
          if (called) {
            assert.deepEqual(reply, {
              jsonrpc: "2.0",
              id: "e",
              result: { protocolVersion: "draft", effects: [] },
            });
          } else {
            // The validator may report invalid params or throw at a different
            // recursion depth on each supported Node version. Both stay safe.
            assert.ok([-32602, -32004].includes(reply.error?.code));
            assert.deepEqual(reply, {
              jsonrpc: "2.0",
              id: "e",
              error: {
                code: reply.error.code,
                message:
                  reply.error.code === -32602
                    ? "Invalid params"
                    : "Backend internal error",
              },
            });
          }
        }
      });
    }
  }
}
