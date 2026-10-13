import test from "node:test";
import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { hooks } from "agenthooksprotocol/server";
import { serveStdio } from "agenthooksprotocol/server/stdio";

const event = (id = "e") => ({
  id,
  source: "urn:test:server", harness: { name: 'test', version: '1' },
  time: "2026-01-01T00:00:00Z",
  type: "tool.before",
  path: "native",
  call: { id: "call" },
  tool: { name: "read", origin: "native", input: {} },
});
const intercept = (id = "e") => ({
  jsonrpc: "2.0",
  id,
  method: "hooks/intercept",
  params: {
    protocolVersion: "draft",
    capabilities: { effects: ["deny"] },
    event: event(id),
  },
});
const observe = () => ({
  jsonrpc: "2.0",
  method: "hooks/observe",
  params: { protocolVersion: "draft", event: event() },
});
const capabilities = (id = "caps") => ({
  jsonrpc: "2.0",
  id,
  method: "hooks/capabilities",
  params: { protocolVersion: "draft" },
});
const request = (value) =>
  new Request("https://backend.test/hooks", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  });
const errorOf = async (value, handlers) => {
  const response = await hooks.handle(request(value), handlers);
  assert.equal(response.status, 200);
  return await response.json();
};

test("missing capabilities handler is method not found", async () => {
  assert.deepEqual(
    await errorOf(capabilities(), { intercept: { toolBefore: () => ({}) } }),
    {
      jsonrpc: "2.0",
      id: "caps",
      error: { code: -32601, message: "Method not found" },
    },
  );
});

test("intercept without a registered handler is unsupported_event", async () => {
  assert.deepEqual(
    await errorOf(intercept(), { intercept: { toolAfter: () => ({}) } }),
    {
      jsonrpc: "2.0",
      id: "e",
      error: { code: -32002, message: "Unsupported event" },
    },
  );
  assert.equal(
    (await errorOf(intercept(), { observe: { toolBefore() {} } })).error.code,
    -32002,
  );
});

test("handler throws and rejections are backend_internal_error without leaking", async () => {
  for (const handlers of [
    {
      intercept: {
        toolBefore: () => {
          throw new Error("Bearer SECRET");
        },
      },
    },
    {
      intercept: {
        toolBefore: async () => {
          throw new Error("Bearer SECRET");
        },
      },
    },
  ]) {
    const body = await errorOf(intercept(), handlers);
    assert.deepEqual(body.error, {
      code: -32004,
      message: "Backend internal error",
    });
    assert.doesNotMatch(JSON.stringify(body), /SECRET/);
  }
  const caps = await errorOf(capabilities(), {
    capabilities: () => {
      throw new Error("Bearer SECRET");
    },
  });
  assert.deepEqual(caps.error, {
    code: -32004,
    message: "Backend internal error",
  });
});

test("unsupported protocol version advertises supported versions", async () => {
  const message = intercept();
  message.params.protocolVersion = "1999-01-01";
  assert.deepEqual(
    await errorOf(message, { intercept: { toolBefore: () => assert.fail() } }),
    {
      jsonrpc: "2.0",
      id: "e",
      error: {
        code: -32001,
        message: "Unsupported AHP protocol version",
        data: { supported: ["draft"] },
      },
    },
  );
});

test("missing observer is a silent success, distinct from observer failure", async () => {
  const absent = await hooks.handle(request(observe()), {
    intercept: { toolBefore: () => assert.fail() },
  });
  assert.equal(absent.status, 204);
  assert.equal(await absent.text(), "");
  const other = await hooks.handle(request(observe()), {
    observe: { toolAfter: () => assert.fail() },
  });
  assert.equal(other.status, 204);
  const failed = await hooks.handle(request(observe()), {
    observe: {
      toolBefore() {
        throw new Error("Bearer SECRET");
      },
    },
  });
  assert.equal(failed.status, 500);
  assert.equal(await failed.text(), "");
});

test("stdio writes no frame for any notification outcome", async () => {
  const wrongVersion = observe();
  wrongVersion.params.protocolVersion = "1999-01-01";
  const invalid = observe();
  invalid.params.event.time = "invalid";
  const notifications = [
    observe(), // missing observer
    wrongVersion,
    invalid,
    { jsonrpc: "2.0", method: "hooks/unknown", params: {} },
    { ...capabilities(), id: undefined },
  ].map((value) => JSON.stringify(value));
  let output = "";
  const stdout = new Writable({
    write(chunk, _encoding, done) {
      output += chunk;
      done();
    },
  });
  await serveStdio(
    { intercept: { toolAfter: () => assert.fail() } },
    { stdin: Readable.from([notifications.join("\n") + "\n"]), stdout },
  );
  assert.equal(output, "");
  await serveStdio(
    {
      observe: {
        toolBefore() {
          throw new Error("Bearer SECRET");
        },
      },
    },
    { stdin: Readable.from([JSON.stringify(observe()) + "\n"]), stdout },
  );
  assert.equal(output, "");
});

test("stdio requests carry the corrected error codes", async () => {
  let output = "";
  const stdout = new Writable({
    write(chunk, _encoding, done) {
      output += chunk;
      done();
    },
  });
  await serveStdio(
    { intercept: { toolAfter: () => ({}) } },
    {
      stdin: Readable.from([
        [JSON.stringify(capabilities()), JSON.stringify(intercept())].join(
          "\n",
        ) + "\n",
      ]),
      stdout,
    },
  );
  const replies = output
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.deepEqual(
    replies.map((reply) => [reply.id, reply.error.code]),
    [
      ["caps", -32601],
      ["e", -32002],
    ],
  );
});

test("catch-all observer runs only when the event has no observer of its own", async () => {
  const seen = [];
  const handlers = {
    observe: {
      toolAfter: () => assert.fail("other event"),
      any(ctx) {
        seen.push([ctx.event.type, ctx.notification.method]);
      },
    },
  };
  const response = await hooks.handle(request(observe()), handlers);
  assert.equal(response.status, 204);
  assert.deepEqual(seen, [["tool.before", "hooks/observe"]]);
  handlers.observe.toolBefore = () => {
    seen.push("own");
  };
  assert.equal((await hooks.handle(request(observe()), handlers)).status, 204);
  assert.deepEqual(seen.at(-1), "own");
  assert.equal(seen.length, 2);
});

test("catch-all observer failures and returned values match per-event observers", async () => {
  for (const any of [
    () => {
      throw new Error("Bearer SECRET");
    },
    () => ({ effects: [] }),
  ]) {
    const response = await hooks.handle(request(observe()), {
      observe: { any },
    });
    assert.equal(response.status, 500);
    assert.equal(await response.text(), "");
  }
  const intercepted = await hooks.handle(request(intercept()), {
    observe: { any: () => assert.fail("intercept") },
  });
  assert.equal((await intercepted.json()).error.code, -32002);
});
