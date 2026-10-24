import test from "node:test";
import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { content, duration, events, subscription } from "agenthooksprotocol";
import { hooks } from "agenthooksprotocol/server";
import { serveStdio } from "agenthooksprotocol/server/stdio";

const configuration = (timeout = 750) => ({ subscriptions: [subscription.intercept({
  events: [events.toolBefore], timeout: duration.milliseconds(timeout),
  failurePolicy: "fail-open", content: content.metadata(),
})] });
const discovery = (id = "configuration") => ({ jsonrpc: "2.0", id,
  method: "hooks/configuration", params: { protocolVersion: "draft" } });
const request = (message = discovery(), signal) => new Request("https://backend.test/hooks", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify(message), ...(signal ? { signal } : {}),
});
const plain = value => JSON.parse(JSON.stringify(value));

// Correlation IDs here identify test requests, not authenticated tenants.
test("dynamic configuration gets the validated request and its current signal on every invocation", async () => {
  const observed = [];
  const handlers = { configuration(context) {
    observed.push(context);
    assert.equal("principal" in context, false);
    return configuration(context.request.id === "first" ? 100 : 200);
  } };
  const firstRequest = request(discovery("first"));
  const first = await (await hooks.handle(firstRequest, handlers)).json();
  const secondRequest = request(discovery("second"));
  const second = await (await hooks.handle(secondRequest, handlers)).json();
  assert.equal(observed.length, 2);
  assert.deepEqual(observed[0].request, discovery("first"));
  assert.equal(observed[0].signal, firstRequest.signal);
  assert.equal(observed[1].signal, secondRequest.signal);
  assert.equal(first.id, "first");
  assert.equal(second.id, "second");
  assert.equal(first.result.configuration.subscriptions[0].timeoutMs, 100);
  assert.equal(second.result.configuration.subscriptions[0].timeoutMs, 200);
});

test("application-authenticated routing can capture tenant configuration without trusting request metadata", async () => {
  const configurations = { approved: configuration(100), other: configuration(200) };
  const applicationRoute = async (incoming, authenticatedTenant) => {
    if (!authenticatedTenant) return new Response(null, { status: 401 });
    return hooks.handle(incoming, { configuration: async () => configurations[authenticatedTenant] });
  };
  assert.equal((await applicationRoute(request(), undefined)).status, 401);
  const response = await applicationRoute(request(discovery("other")), "approved");
  assert.equal((await response.json()).result.configuration.subscriptions[0].timeoutMs, 100);
});

test("dynamic results and callback request mutation cannot change saved correlation or earlier responses", async () => {
  const shared = configuration(100);
  const handlers = { configuration: async context => {
    context.request.id = "mutated";
    context.request.params.protocolVersion = "invalid";
    return shared;
  } };
  const first = await hooks.handle(request(discovery("first")), handlers);
  shared.subscriptions[0].timeoutMs = 200;
  const second = await hooks.handle(request(discovery("second")), handlers);
  const firstBody = await first.json();
  const secondBody = await second.json();
  assert.equal(firstBody.id, "first");
  assert.equal(firstBody.result.protocolVersion, "draft");
  assert.equal(firstBody.result.configuration.subscriptions[0].timeoutMs, 100);
  assert.equal(secondBody.id, "second");
  assert.equal(secondBody.result.configuration.subscriptions[0].timeoutMs, 200);
});

test("malformed discovery and unsupported versions never invoke dynamic configuration", async () => {
  let calls = 0;
  const handlers = { configuration() { calls++; return configuration(); } };
  for (const [message, code] of [
    [{ ...discovery(), params: {} }, -32602],
    [{ ...discovery(), params: { protocolVersion: "unknown" } }, -32001],
    [{ ...discovery(), jsonrpc: "1.0" }, -32600],
  ]) {
    const response = await (await hooks.handle(request(message), handlers)).json();
    assert.equal(response.error.code, code);
  }
  const notification = discovery(); delete notification.id;
  assert.equal(await (await hooks.handle(request(notification), handlers)).text(), "");
  assert.equal(calls, 0);
});

for (const [label, callback] of [
  ["throw", () => { throw Error("private credentials"); }],
  ["rejection", async () => { throw Error("private credentials"); }],
  ["undefined", () => undefined],
  ["null", async () => null],
  ["empty subscriptions", () => ({ subscriptions: [] })],
  ["invalid subscription", () => ({ subscriptions: [{ events: ["tool.before"], mode: "intercept" }] })],
  ["uncloneable value", () => ({ ...configuration(), private: () => "private credentials" })],
]) {
  test(`dynamic ${label} produces only a sanitized backend failure`, async () => {
    const body = await (await hooks.handle(request(), { configuration: callback })).json();
    assert.deepEqual(body, { jsonrpc: "2.0", id: "configuration",
      error: { code: -32004, message: "Backend internal error" } });
  });
}

test("missing configuration remains method-not-found rather than dynamic nil", async () => {
  const response = await hooks.handle(request(), { intercept: { toolBefore: () => ({}) } });
  assert.equal((await response.json()).error.code, -32601);
});

test("static declarations retain the snapshot from their first discovery", async () => {
  const cfg = configuration(100);
  const handlers = { configuration: cfg };
  const first = await (await hooks.handle(request(discovery("first")), handlers)).json();
  cfg.subscriptions[0].timeoutMs = 200;
  const second = await (await hooks.handle(request(discovery("second")), handlers)).json();
  assert.deepEqual(first.result.configuration, plain(configuration(100)));
  assert.deepEqual(second.result.configuration, first.result.configuration);
});

test("an already-aborted discovery does not invoke the dynamic callback", async () => {
  const controller = new AbortController(); controller.abort(Error("private cancellation"));
  let calls = 0;
  const response = await hooks.handle(request(discovery(), controller.signal), { configuration() {
    calls++; return configuration();
  } });
  assert.equal(calls, 0);
  assert.equal((await response.json()).error.code, -32004);
});

test("HTTP cancellation reaches the dynamic context and retires an uncooperative callback", async () => {
  const controller = new AbortController();
  let started, context;
  const ready = new Promise(resolve => { started = resolve; });
  const work = hooks.handle(request(discovery(), controller.signal), { configuration(ctx) {
    context = ctx; started();
    return new Promise(() => {});
  } });
  await ready;
  controller.abort(Error("private cancellation"));
  const response = await work;
  assert.equal(context.signal.aborted, true);
  assert.deepEqual((await response.json()).error, { code: -32004, message: "Backend internal error" });
});

test("HTTP and stdio invoke the same async configuration callback and preserve correlation", async () => {
  const seen = [];
  const handlers = { configuration: async context => { seen.push(context.request.id); return configuration(); } };
  let output = "";
  await serveStdio(handlers, {
    stdin: Readable.from([JSON.stringify(discovery("stdio")) + "\n"]),
    stdout: new Writable({ write(chunk, _encoding, done) { output += chunk; done(); } }),
  });
  const http = await (await hooks.handle(request(discovery("http")), handlers)).json();
  const stdio = JSON.parse(output);
  assert.deepEqual(stdio.result, http.result);
  assert.equal(stdio.id, "stdio");
  assert.deepEqual(seen, ["stdio", "http"]);
});

test("stdio cancellation reaches configuration context and stops the serving pipeline", async () => {
  const controller = new AbortController();
  let started, context;
  const ready = new Promise(resolve => { started = resolve; });
  const work = serveStdio({ configuration(ctx) {
    context = ctx; started(); return new Promise(() => {});
  } }, {
    stdin: Readable.from([JSON.stringify(discovery()) + "\n"]),
    stdout: new Writable({ write(_chunk, _encoding, done) { done(); } }), signal: controller.signal,
  });
  const rejected = assert.rejects(work, { name: "AbortError" });
  await ready; controller.abort();
  await rejected;
  assert.equal(context.signal.aborted, true);
});

test("configuration callbacks are not invoked for ordinary event requests", async () => {
  let configurations = 0, observations = 0;
  const response = await hooks.handle(request({ jsonrpc: "2.0", method: "hooks/observe", params: {
    protocolVersion: "draft", event: { type: "tool.before", id: "event", source: "urn:test",
      harness: { name: "test", version: "1" }, time: "2026-01-01T00:00:00Z", call: { id: "call" },
      path: "native", tool: { name: "read", origin: "native", input: {} } },
  } }), { configuration() { configurations++; return configuration(); }, observe: { toolBefore() { observations++; } } });
  assert.equal(response.status, 204);
  assert.equal(configurations, 0);
  assert.equal(observations, 1);
});

test("dynamic and static configuration types compile through public entrypoints", () => {
  const require = createRequire(import.meta.url);
  const result = spawnSync(process.execPath, [require.resolve("typescript/bin/tsc"), "--noEmit", "--strict", "--exactOptionalPropertyTypes", "--target", "ES2022", "--module", "NodeNext", "--moduleResolution", "NodeNext", new URL("./dynamic-configuration-types.ts", import.meta.url).pathname, new URL("../../../node-shims.d.ts", import.meta.url).pathname], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
