import test from "node:test";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { createServer } from "node:http";
import { once } from "node:events";
import { Hooks, Attachment, auth } from "agenthooksprotocol/client";
import { createHash } from "node:crypto";
import { hooks } from "agenthooksprotocol/server";
import { serveStdio } from "agenthooksprotocol/server/stdio";
import { content, duration, events, subscription } from "agenthooksprotocol";

const selected = () => subscription.intercept({
  events: [events.toolBefore], timeout: duration.milliseconds(750),
  failurePolicy: "fail-open", content: content.metadata(),
});
const configuration = () => ({ subscriptions: [selected()] });
const request = (id = "configuration") => ({ jsonrpc: "2.0", id,
  method: "hooks/configuration", params: { protocolVersion: "draft" } });
const http = message => new Request("https://backend.test/hooks", {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(message),
});
const registration = (subscriptions) => ({ protocolVersion: "draft", hooks: [{
  id: "test.backend", transport: { type: "http", url: "https://backend.test/hooks" },
  ...(subscriptions === undefined ? {} : { subscriptions }),
}] });
const options = fetch => ({ source: "urn:test:configuration", harness: { name: "test", version: "1" },
  capabilities: { toolBefore: { intercept: { deny: true } } }, fetch,
});
const input = { callId: "call", name: "read", path: "native", origin: "native", input: {} };

test("public configuration helpers produce canonical shared subscriptions", () => {
  assert.deepEqual(JSON.parse(JSON.stringify(selected())), { events: ["tool.before"], mode: "intercept", timeoutMs: 750,
    failurePolicy: "fail-open", content: { default: "metadata" } });
  assert.throws(() => duration.milliseconds(0));
  assert.throws(() => duration.milliseconds(1.5));
});

test("server advertises a snapshot and does not invoke event handlers", async () => {
  const declaration = configuration();
  const handlers = { configuration: declaration, intercept: { toolBefore() { throw new Error("not an event"); } } };
  const first = await (await hooks.handle(http(request()), handlers)).json();
  assert.deepEqual(first.result, { protocolVersion: "draft", configuration: JSON.parse(JSON.stringify(declaration)) });
  declaration.subscriptions[0].timeoutMs = 1;
  const second = await (await hooks.handle(http(request("second")), handlers)).json();
  assert.equal(second.id, "second");
  assert.equal(second.result.configuration.subscriptions[0].timeoutMs, 750);
});

test("server rejects unsupported version, malformed request and invalid declarations", async () => {
  for (const [message, handlers, code] of [
    [request(), { intercept: { toolBefore: () => ({}) } }, -32601],
    [{ ...request(), params: {} }, { configuration: configuration() }, -32602],
    [{ ...request(), params: { protocolVersion: "unknown" } }, { configuration: configuration() }, -32001],
    [request(), { configuration: { subscriptions: [] } }, -32004],
  ]) {
    const result = await (await hooks.handle(http(message), handlers)).json();
    assert.equal(result.error.code, code);
  }
});

test("stdio exposes the same static configuration without starting an event", async () => {
  let output = "";
  await serveStdio({ configuration: configuration() }, {
    stdin: Readable.from([JSON.stringify(request()) + "\n"]),
    stdout: new Writable({ write(chunk, _encoding, done) { output += chunk; done(); } }),
  });
  assert.deepEqual(JSON.parse(output).result.configuration, JSON.parse(JSON.stringify(configuration())));
});

test("initialization discovers defaults through configured headers, then dispatches normally", async () => {
  const calls = [];
  const config = registration();
  config.hooks[0].transport.headers = { Authorization: "Bearer configured", "X-Backend": "tenant" };
  const handlers = { configuration: configuration(), intercept: { toolBefore: () => ({}) } };
  const client = new Hooks(config, options(async (url, init) => {
    calls.push(JSON.parse(init.body));
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer configured");
    assert.equal(new Headers(init.headers).get("x-backend"), "tenant");
    return hooks.handle(new Request(url, init), handlers);
  }));
  try {
    await client.initialized;
    assert.equal(client.intercepts(events.toolBefore), true);
    await client.toolBefore(input);
    assert.deepEqual(calls.map(call => call.method), ["hooks/configuration", "hooks/intercept"]);
    assert.deepEqual(calls[1].params.capabilities.effects, ["deny"]);
    assert.deepEqual(client.initializationDiagnostics, []);
  } finally { await client.close(); }
});

test("explicit subscriptions bypass discovery and retain synchronous interest", async () => {
  const methods = [];
  const client = new Hooks(registration([selected()]), options(async (_url, init) => {
    const message = JSON.parse(init.body); methods.push(message.method);
    return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft", effects: [] } });
  }));
  try {
    assert.equal(client.intercepts(events.toolBefore), true);
    await client.initialized;
    assert.deepEqual(methods, []);
    await client.toolBefore(input);
    assert.deepEqual(methods, ["hooks/intercept"]);
  } finally { await client.close(); }
});

test("explicit empty configuration is invalid rather than a discovery opt-in", async () => {
  let fetched = false;
  const client = new Hooks(registration([]), options(async () => { fetched = true; throw Error(); }));
  try {
    await assert.rejects(client.initialized, { name: "ConfigurationError" });
    assert.equal(fetched, false);
  } finally { await client.close(); }
});

test("discovered wildcards select supported modes and do not broaden grants", async () => {
  const cfg = { subscriptions: [
    { ...selected(), events: ["tool.*"] },
    { mode: "observe", events: ["session.end"], content: { default: "metadata" } },
  ] };
  const client = new Hooks(registration(), options(async (_url, init) => {
    const message = JSON.parse(init.body);
    return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft", configuration: cfg } });
  }));
  try {
    await client.initialized;
    assert.equal(client.intercepts(events.toolBefore), true);
    assert.equal(client.subscribes(events.toolAfter), false);
    assert.equal(client.subscribes(events.sessionEnd), false);
  } finally { await client.close(); }
});

for (const failure of ["unavailable", "malformed", "version", "correlation", "unsupported", "timeout"]) {
  test(`discovery ${failure} skips only that backend`, async () => {
    const client = new Hooks(registration(), { ...options(async (_url, init) => {
      if (failure === "unavailable") return new Response(null, { status: 503 });
      if (failure === "timeout") return new Promise(() => {});
      const message = JSON.parse(init.body);
      return Response.json({ jsonrpc: "2.0", id: failure === "correlation" ? "wrong" : message.id,
        result: { protocolVersion: failure === "version" ? "wrong" : "draft", configuration:
          failure === "malformed" ? { subscriptions: [] } : failure === "unsupported"
            ? { subscriptions: [{ mode: "observe", events: ["session.end"], content: { default: "metadata" } }] }
            : configuration() } });
    }), configurationTimeoutMs: 30 });
    try {
      await client.initialized;
      assert.equal(client.subscribes(events.toolBefore), false);
      assert.equal(client.initializationDiagnostics.length, 1);
      assert.equal(client.initializationDiagnostics[0].code,
        failure === "unsupported" ? "NO_APPLICABLE_SUBSCRIPTIONS" : "CONFIGURATION_UNAVAILABLE");
    } finally { await client.close(); }
  });
}

test("close cancels discovery and waits for owned initialization", async () => {
  let start;
  const started = new Promise(resolve => { start = resolve; });
  const client = new Hooks(registration(), options(async () => { start(); return new Promise(() => {}); }));
  await started;
  await client.close();
  await assert.rejects(client.initialized);
  assert.equal(client.subscribes(events.toolBefore), false);
});


test("shared configuration declarations compile through public entrypoints", () => {
  const require = createRequire(import.meta.url);
  const result = spawnSync(process.execPath, [require.resolve("typescript/bin/tsc"), "--noEmit", "--strict", "--exactOptionalPropertyTypes", "--target", "ES2022", "--module", "NodeNext", "--moduleResolution", "NodeNext", new URL("./configuration-types.ts", import.meta.url).pathname, new URL("../../../node-shims.d.ts", import.meta.url).pathname], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

for (const lifecycle of ["persistent", "per_event"]) {
  test(`stdio ${lifecycle} discovers and dispatches with owned shutdown`, async () => {
    const script = `
      const readline = require('node:readline');
      const input = readline.createInterface({ input: process.stdin });
      input.on('line', line => {
        const request = JSON.parse(line);
        const result = request.method === 'hooks/configuration'
          ? { protocolVersion: 'draft', configuration: ${JSON.stringify({ subscriptions: [{ mode: "intercept", events: ["tool.before"], timeoutMs: 750, failurePolicy: "fail-open", content: { default: "metadata" } }] })} }
          : { protocolVersion: 'draft', effects: [{ type: 'deny', reason: 'configured' }] };
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\\n', () => {
          if (${JSON.stringify(lifecycle)} === 'per_event') process.exit(0);
        });
      });
    `;
    const cfg = registration();
    cfg.hooks[0].transport = { type: "stdio", command: process.execPath, args: ["-e", script], lifecycle };
    const client = new Hooks(cfg, options());
    try {
      await client.initialized;
      assert.equal(client.intercepts(events.toolBefore), true);
      const result = await client.toolBefore(input);
      assert.equal(result.effects[0].type, "deny");
    } finally { await client.close(); }
  });
}

test("concurrent discovery preserves registration order and isolates skipped backends", async () => {
  const cfg = registration();
  cfg.hooks = ["first", "missing", "last"].map(name => ({ id: `test.${name}`,
    transport: { type: "http", url: `https://backend.test/${name}` } }));
  const called = [];
  const client = new Hooks(cfg, options(async (url, init) => {
    const message = JSON.parse(init.body);
    const name = new URL(url).pathname.slice(1);
    if (message.method === "hooks/configuration") {
      if (name === "missing") return new Response(null, { status: 503 });
      if (name === "first") await new Promise(resolve => setTimeout(resolve, 15));
      return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft", configuration: configuration() } });
    }
    called.push(name);
    return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft", effects: [] } });
  }));
  try {
    await client.initialized;
    await client.toolBefore(input);
    assert.deepEqual(called, ["first", "last"]);
    assert.deepEqual(client.initializationDiagnostics, [{ backendId: "test.missing", code: "CONFIGURATION_UNAVAILABLE" }]);
  } finally { await client.close(); }
});


test("HTTP discovery and interception cross the real client/server transport", async () => {
  const handlers = { configuration: configuration(), intercept: { toolBefore: () => ({ effects: [{ type: "deny", reason: "configured" }] }) } };
  const methods = [];
  const server = createServer(async (incoming, outgoing) => {
    const chunks = [];
    for await (const chunk of incoming) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    methods.push(JSON.parse(body).method);
    const response = await hooks.handle(new Request("http://127.0.0.1/hooks", {
      method: "POST", headers: incoming.headers, body,
    }), handlers);
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(await response.text());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const cfg = registration();
  cfg.hooks[0].transport.url = `http://127.0.0.1:${server.address().port}/hooks`;
  const client = new Hooks(cfg, options());
  try {
    await client.initialized;
    assert.equal(client.intercepts(events.toolBefore), true);
    const result = await client.toolBefore(input);
    assert.equal(result.effects[0].type, "deny");
    assert.deepEqual(methods, ["hooks/configuration", "hooks/intercept"]);
  } finally {
    await client.close();
    await new Promise(resolve => server.close(resolve));
  }
});


const upload = (authentication) => ({ endpoint: "https://upload.test/media", timeoutMs: 1000, maxBytes: 100,
  ...(authentication === undefined ? {} : { auth: authentication }),
});
for (const [kind, binding] of [
  ["environment", { type: "bearer", tokenEnv: "PRIVATE_ENV" }],
  ["reference", { type: "bearer", tokenRef: "private/secret" }],
  ["oauth", { type: "oauth", issuer: "https://issuer.test", resource: "https://upload.test", clientId: "private", flow: "client_credentials", clientSecretRef: "private/oauth" }],
  ["header-only", undefined],
]) {
  test(`unapproved discovered ${kind} upload cannot resolve secrets or forward event headers`, async () => {
    const resolved = [];
    const calls = [];
    const cfg = registration();
    cfg.hooks[0].transport.headers = { Authorization: { valueRef: "event-header" } };
    const client = new Hooks(cfg, { ...options(async (url, init) => {
      calls.push(String(url));
      assert.equal(String(url), "https://backend.test/hooks");
      assert.equal(new Headers(init.headers).get("authorization"), "Bearer event-only");
      const message = JSON.parse(init.body);
      return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft",
        configuration: { subscriptions: [{ ...selected(), upload: upload(binding) }] } } });
    }), auth: auth({
      resolveEnvironmentVariable(name) { resolved.push(name); throw Error("must not resolve environment"); },
      resolveCredentialReference(name) { resolved.push(name); if (name === "event-header") return "Bearer event-only"; throw Error("must not resolve upload credentials"); },
    }) });
    try {
      await client.initialized;
      assert.equal(client.subscribes(events.toolBefore), false);
      assert.deepEqual(calls, ["https://backend.test/hooks"]);
      assert.deepEqual(resolved, ["event-header"]);
      assert.equal(client.initializationDiagnostics[0].code, "CONFIGURATION_NOT_AUTHORIZED");
    } finally { await client.close(); }
  });
}

for (const decision of [false, "throw"]) {
  test(`upload authorization ${decision} skips the complete backend`, async () => {
    const cfg = { subscriptions: [{ ...selected(), upload: upload() }] };
    const client = new Hooks(registration(), { ...options(async (_url, init) => {
      const message = JSON.parse(init.body);
      return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft", configuration: cfg } });
    }), authorizeDiscoveredConfiguration(configuration, context) {
      assert.deepEqual(configuration, cfg);
      assert.equal(context.backendId, "test.backend");
      if (decision === "throw") throw Error("private denial reason");
      return false;
    } });
    try {
      await client.initialized;
      assert.equal(client.intercepts(events.toolBefore), false);
      assert.equal(client.initializationDiagnostics.length, 1);
      assert.equal(JSON.stringify(client.initializationDiagnostics).includes("private"), false);
    } finally { await client.close(); }
  });
}

test("explicit approval authorizes the complete detached upload configuration without rewriting it", async () => {
  const cfg = registration();
  cfg.hooks[0].transport.headers = { Authorization: "Bearer approved-forwarding" };
  const declaration = { subscriptions: [{ ...selected(), content: { default: "body" }, upload: upload() }] };
  const calls = [];
  const client = new Hooks(cfg, { ...options(async (url, init) => {
    calls.push(String(url));
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer approved-forwarding");
    if (String(url) === "https://upload.test/media") {
      return Response.json({ ref: "uploaded:body", size: init.body.byteLength,
        sha256: createHash("sha256").update(init.body).digest("hex") }, { status: 201 });
    }
    const message = JSON.parse(init.body);
    return Response.json({ jsonrpc: "2.0", id: message.id, result: message.method === "hooks/configuration"
      ? { protocolVersion: "draft", configuration: declaration } : { protocolVersion: "draft", effects: [] } });
  }), authorizeDiscoveredConfiguration(configuration, context) {
    assert.deepEqual(configuration, declaration);
    assert.equal(context.backendId, "test.backend");
    configuration.subscriptions[0].upload.endpoint = "https://mutation.test/not-authorized";
    return true;
  } });
  try {
    await client.initialized;
    assert.equal(client.intercepts(events.toolBefore), true);
    const result = await client.toolBefore({ ...input, items: [{ id: "body", kind: "attachment", selection: "body",
      mediaType: "application/octet-stream", body: Attachment.bytes(new Uint8Array([1, 2, 3])) }] });
    assert.deepEqual(result.diagnostics, []);
    assert.deepEqual(calls, ["https://backend.test/hooks", "https://upload.test/media", "https://backend.test/hooks"]);
  } finally { await client.close(); }
});

test("upload approval is bounded by the initialization deadline", async () => {
  let signal;
  const client = new Hooks(registration(), { ...options(async (_url, init) => {
    const message = JSON.parse(init.body);
    return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft",
      configuration: { subscriptions: [{ ...selected(), upload: upload() }] } } });
  }), configurationTimeoutMs: 30,
  authorizeDiscoveredConfiguration(_configuration, context) {
    signal = context.signal;
    return new Promise(() => {});
  } });
  try {
    await client.initialized;
    assert.equal(signal.aborted, true);
    assert.equal(client.intercepts(events.toolBefore), false);
    assert.equal(client.initializationDiagnostics[0].code, "CONFIGURATION_UNAVAILABLE");
  } finally { await client.close(); }
});

test("explicit local upload configuration does not invoke discovery authorization", async () => {
  const client = new Hooks(registration([{ ...selected(), upload: upload({ type: "bearer", tokenRef: "local" }) }]), {
    ...options(async () => { throw Error("initialization must not fetch"); }),
    authorizeDiscoveredConfiguration() { throw Error("must not authorize local configuration"); },
  });
  try {
    await client.initialized;
    assert.equal(client.intercepts(events.toolBefore), true);
    assert.deepEqual(client.initializationDiagnostics, []);
  } finally { await client.close(); }
});

test("wildcard helpers remain selectors rather than actual runtime events", async () => {
  const { isEventType } = await import("../dist/src/client/validation.js");
  assert.equal(isEventType(events.all), false);
  assert.equal(isEventType(events.tool.all), false);
  assert.equal(isEventType(events.tool), false);
  assert.equal(isEventType(events.toolBefore), true);
  const cfg = configuration();
  cfg.subscriptions[0].events = [events.tool.all];
  const client = new Hooks(registration(cfg.subscriptions), options());
  try {
    await client.initialized;
    assert.equal(client.subscribes(events.toolBefore), true);
  } finally { await client.close(); }
});
