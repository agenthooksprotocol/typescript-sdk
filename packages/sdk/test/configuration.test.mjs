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
        failure === "unsupported" ? "no_applicable_subscriptions"
          : ["malformed", "version", "correlation"].includes(failure) ? "configuration_invalid" : "configuration_unavailable");
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
    assert.deepEqual(client.initializationDiagnostics, [{ backendId: "test.missing", code: "configuration_unavailable" }]);
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
const oauth = { type: "oauth", issuer: "https://issuer.test", resource: "https://upload.test", clientId: "private", flow: "client_credentials" };

for (const [kind, binding] of [
  ["tokenEnv", { type: "bearer", tokenEnv: "PRIVATE_TOKEN" }],
  ["tokenRef", { type: "bearer", tokenRef: "private/secret" }],
  ["clientSecretRef", { ...oauth, clientSecretRef: "private/secret" }],
]) {
  test(`discovered upload naming ${kind} skips the backend before anything is resolved`, async () => {
    const resolved = [];
    const calls = [];
    const client = new Hooks(registration(), { ...options(async (url, init) => {
      calls.push(String(url));
      const message = JSON.parse(init.body);
      return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft",
        configuration: { subscriptions: [{ ...selected(), upload: upload(binding) }] } } });
    }), auth: auth({
      resolveEnvironmentVariable(name) { resolved.push(name); throw Error("must not resolve environment"); },
      resolveCredentialReference(name) { resolved.push(name); throw Error("must not resolve reference"); },
    }) });
    try {
      await client.initialized;
      assert.equal(client.subscribes(events.toolBefore), false);
      assert.deepEqual(calls, ["https://backend.test/hooks"]);
      assert.deepEqual(resolved, []);
      assert.equal(client.initializationDiagnostics[0].code, "configuration_local_secret");
    } finally { await client.close(); }
  });
}

test("discovered upload is admitted, and configured backend headers apply to it", async () => {
  const cfg = registration();
  cfg.hooks[0].transport.headers = { Authorization: "Bearer configured" };
  const declaration = { subscriptions: [{ ...selected(), content: { default: "body" }, upload: upload() }] };
  const calls = [];
  const client = new Hooks(cfg, options(async (url, init) => {
    calls.push(String(url));
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer configured");
    if (String(url) === "https://upload.test/media") {
      return Response.json({ ref: "uploaded:body", size: init.body.byteLength,
        sha256: createHash("sha256").update(init.body).digest("hex") }, { status: 201 });
    }
    const message = JSON.parse(init.body);
    return Response.json({ jsonrpc: "2.0", id: message.id, result: message.method === "hooks/configuration"
      ? { protocolVersion: "draft", configuration: declaration } : { protocolVersion: "draft", effects: [] } });
  }));
  try {
    await client.initialized;
    assert.deepEqual(client.initializationDiagnostics, []);
    assert.equal(client.intercepts(events.toolBefore), true);
    const result = await client.toolBefore({ ...input, items: [{ id: "body", kind: "attachment", selection: "body",
      mediaType: "application/octet-stream", body: Attachment.bytes(new Uint8Array([1, 2, 3])) }] });
    assert.deepEqual(result.diagnostics, []);
    assert.deepEqual(calls, ["https://backend.test/hooks", "https://upload.test/media", "https://backend.test/hooks"]);
  } finally { await client.close(); }
});

test("discovered upload with OAuth and no client secret reference is admitted", async () => {
  const client = new Hooks(registration(), options(async (_url, init) => {
    const message = JSON.parse(init.body);
    return Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft",
      configuration: { subscriptions: [{ ...selected(), upload: upload(oauth) }] } } });
  }));
  try {
    await client.initialized;
    assert.deepEqual(client.initializationDiagnostics, []);
    assert.equal(client.intercepts(events.toolBefore), true);
  } finally { await client.close(); }
});

test("explicit local upload configuration may name local secrets", async () => {
  const client = new Hooks(registration([{ ...selected(), upload: upload({ type: "bearer", tokenRef: "local" }) }]),
    options(async () => { throw Error("initialization must not fetch"); }));
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

test("configuration-auth-diagnostic: an auth failure during discovery carries the login hint", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  const cfg = registration();
  cfg.hooks = [{ id: "test.login", transport: { type: "http", url: "https://backend.test/login" },
    authentication: { type: "oauth", issuer: "https://issuer.test", resource: "https://backend.test", clientId: "c",
      flow: "authorization_code_pkce", scopes: ["read"] } }];
  let sent = 0;
  const provider = { credential() { throw new AuthError("interaction_required", ["read"]); }, challenge() {} };
  const client = new Hooks(cfg, { ...options(async () => { sent++; return new Response(null, { status: 500 }); }), auth: provider });
  try {
    await client.initialized;
    assert.equal(sent, 0);
    assert.deepEqual(client.initializationDiagnostics, [{ backendId: "test.login", code: "configuration_unavailable",
      authError: "interaction_required", recovery: "login", requiredScopes: ["read"] }]);
  } finally { await client.close(); }
});

// Skipped-backend diagnostics and re-attempts (server-driven configuration, "Skipped backends").
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
/** Dispatch one event, then let a background re-attempt it started settle. */
const admit = async (client, extra = {}) => { const result = await client.toolBefore({ ...input, ...extra }); await sleep(25); return result; };
const advertisement = message => Response.json({ jsonrpc: "2.0", id: message.id,
  result: { protocolVersion: "draft", configuration: configuration() } });
const accepted = message => Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft", effects: [] } });
/** A host provider that notifies prepares, as managedOAuth's provider does. */
function preparedProvider(credential = () => undefined) {
  const listeners = new Set();
  return {
    provider: { credential, challenge() {}, onPrepared(listener) { listeners.add(listener); return () => listeners.delete(listener); } },
    prepare: endpoint => { for (const listener of listeners) listener(endpoint); },
    listeners,
  };
}
const endpoint = (backendId = "test.backend", url = "https://backend.test/hooks", purpose = "event") => ({ backendId, purpose, url });

test("[configuration-401-diagnostic-carries-auth-code] a 401 discovery with no usable grant reports the safe auth code", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  let challenged = 0;
  const provider = { credential() { return undefined; },
    challenge() { challenged++; throw new AuthError("interaction_required"); } };
  const client = new Hooks(registration(), { ...options(async () => new Response("secret-body access-secret", {
    status: 401, headers: { "www-authenticate": 'Bearer resource_metadata="https://backend.test/.well-known/oauth-protected-resource"' } })),
  auth: provider });
  try {
    await client.initialized;
    assert.equal(challenged, 1);
    assert.deepEqual(plainDiagnostics(client), [{ backendId: "test.backend", code: "configuration_unavailable",
      authError: "interaction_required", recovery: "login" }]);
    assert.doesNotMatch(JSON.stringify(client.initializationDiagnostics), /secret|Bearer|backend\.test/);
  } finally { await client.close(); }
  // Cancellation propagates and emits no skip diagnostic.
  let start;
  const started = new Promise(resolve => { start = resolve; });
  const cancelled = new Hooks(registration(), { ...options(async (_url, init) => {
    start();
    return new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason)));
  }), auth: provider });
  await started;
  await cancelled.close();
  await assert.rejects(cancelled.initialized);
  assert.deepEqual(cancelled.initializationDiagnostics, []);
});
function plainDiagnostics(client) { return JSON.parse(JSON.stringify(client.initializationDiagnostics)); }

test("[configuration-unavailable-retried-after-prepare] a host prepare re-attempts at the next admission without backoff", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  let authorized = false, discoveries = 0;
  const called = [];
  const host = preparedProvider(() => {
    if (!authorized) throw new AuthError("interaction_required");
    return { type: "bearer", token: "prepared" };
  });
  const provider = auth.compose({ oauth: host.provider });
  const cfg = registration();
  cfg.hooks[0].authentication = { type: "oauth", issuer: "https://issuer.test", resource: "https://backend.test",
    clientId: "c", flow: "authorization_code_pkce", scopes: ["read"] };
  const client = new Hooks(cfg, { ...options(async (_url, init) => {
    const message = JSON.parse(init.body);
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer prepared");
    if (message.method === "hooks/configuration") { discoveries++; return advertisement(message); }
    called.push(message.params.event.id);
    return accepted(message);
  }), auth: provider });
  try {
    await client.initialized;
    assert.equal(client.initializationDiagnostics[0].recovery, "login");
    await admit(client);
    assert.equal(discoveries, 0);
    // A prepare for another backend, purpose or URL does not make this one eligible.
    authorized = true;
    host.prepare(endpoint("test.other"));
    host.prepare(endpoint("test.backend", "https://backend.test/hooks", "upload"));
    host.prepare(endpoint("test.backend", "https://backend.test/other"));
    await admit(client);
    assert.equal(discoveries, 0);
    host.prepare(endpoint());
    await admit(client, { callId: "after-prepare" });
    assert.equal(discoveries, 1);
    assert.equal(called.length, 0, "the admitting event uses the routes current at its admission");
    assert.equal(client.intercepts(events.toolBefore), true);
    // Installed once: later admissions neither rediscover nor duplicate routes.
    await admit(client);
    await admit(client);
    assert.equal(discoveries, 1);
    assert.equal(called.length, 2);
  } finally { await client.close(); }
  assert.equal(host.listeners.size, 0, "close unsubscribes from prepare notifications");
});

test("[configuration-unavailable-backoff] an unavailable backend is re-attempted only after its doubling, capped backoff", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  for (const cause of ["status", "retry-auth"]) {
    const attempts = [];
    let delivered = 0;
    let failures = 0;
    const credential = () => {
      if (cause === "retry-auth" && failures < 3) { failures++; attempts.push(Date.now()); throw new AuthError("provider_failed"); }
    };
    const client = new Hooks(registration(), { ...options(async (_url, init) => {
      const message = JSON.parse(init.body);
      if (message.method !== "hooks/configuration") { delivered++; return accepted(message); }
      attempts.push(Date.now());
      return cause === "status" && attempts.length < 4 ? new Response(null, { status: 503 }) : advertisement(message);
    }), auth: { credential, challenge() {} }, configurationRetry: { initialDelayMs: 60, maxDelayMs: 120 } });
    try {
      await client.initialized;
      assert.equal(attempts.length, 1);
      const expected = cause === "status" ? {} : { authError: "provider_failed", recovery: "retry" };
      const { backendId: _id, code: _code, ...authFields } = plainDiagnostics(client)[0];
      assert.deepEqual(authFields, expected);
      await admit(client);
      assert.equal(attempts.length, 1, "no re-attempt before the first backoff ends");
      // Delays 60, 120, then capped at 120: each due admission makes one attempt.
      for (const [wait, count] of [[80, 2], [60, 2], [80, 3], [60, 3], [80, 4]]) {
        await sleep(wait - 25);
        await admit(client);
        assert.equal(attempts.length, count, `after waiting ${wait} ms`);
      }
      assert.ok(attempts[2] - attempts[1] >= 120 && attempts[3] - attempts[2] >= 120);
      assert.equal(delivered, 0, "the admitting event used the routes current at its admission");
      await client.toolBefore(input);
      assert.equal(delivered, 1);
      assert.equal(client.initializationDiagnostics.length, 3);
      assert.ok(client.initializationDiagnostics.every(diagnostic => diagnostic.code === "configuration_unavailable"));
    } finally { await client.close(); }
  }
  await assert.rejects(new Hooks(registration(), { ...options(), configurationRetry: { initialDelayMs: 10, maxDelayMs: 5 } }).initialized,
    error => error.issues?.[0].path === "configurationRetry");
});

test("[configuration-auth-failure-not-retried-on-backoff] login, configure and none recoveries wait for a host prepare", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  for (const [code, recovery] of [["interaction_required", "login"], ["credential_unavailable", "configure"], ["access_denied", "none"]]) {
    let attempts = 0, authorized = false;
    const host = preparedProvider(() => {
      attempts++;
      if (!authorized) throw new AuthError(code);
    });
    const client = new Hooks(registration(), { ...options(async (_url, init) => advertisement(JSON.parse(init.body))),
      auth: host.provider, configurationRetry: { initialDelayMs: 5, maxDelayMs: 5 } });
    try {
      await client.initialized;
      assert.deepEqual(plainDiagnostics(client), [{ backendId: "test.backend", code: "configuration_unavailable", authError: code, recovery }]);
      await sleep(30);
      await admit(client);
      await sleep(30);
      await admit(client);
      assert.equal(attempts, 1, `${recovery} is not re-attempted on backoff`);
      assert.equal(client.intercepts(events.toolBefore), false);
      authorized = true;
      host.prepare(endpoint());
      await admit(client);
      assert.equal(client.intercepts(events.toolBefore), true);
    } finally { await client.close(); }
  }
});

test("[configuration-invalid-not-retried] invalid, inapplicable and local-secret skips are never re-attempted", async () => {
  const cases = {
    "configuration_invalid": message => Response.json({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } }),
    "no_applicable_subscriptions": message => Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft",
      configuration: { subscriptions: [{ mode: "observe", events: ["session.end"], content: { default: "metadata" } }] } } }),
    "configuration_local_secret": message => Response.json({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "draft",
      configuration: { subscriptions: [{ ...selected(), upload: upload({ type: "bearer", tokenEnv: "LOCAL" }) }] } } }),
  };
  for (const [code, respond] of Object.entries(cases)) {
    let discoveries = 0;
    const host = preparedProvider();
    const client = new Hooks(registration(), { ...options(async (_url, init) => {
      const message = JSON.parse(init.body);
      if (message.method === "hooks/configuration") discoveries++;
      return respond(message);
    }), auth: host.provider, configurationRetry: { initialDelayMs: 5, maxDelayMs: 5 } });
    try {
      await client.initialized;
      assert.deepEqual(plainDiagnostics(client), [{ backendId: "test.backend", code }]);
      host.prepare(endpoint());
      await sleep(30);
      await admit(client);
      await admit(client);
      assert.equal(discoveries, 1, code);
      assert.equal(client.initializationDiagnostics.length, 1);
    } finally { await client.close(); }
  }
  // A JSON-RPC error other than method-not-found is unavailable, not invalid.
  const unavailable = new Hooks(registration(), options(async (_url, init) =>
    Response.json({ jsonrpc: "2.0", id: JSON.parse(init.body).id, error: { code: -32004, message: "Backend internal error" } })));
  try {
    await unavailable.initialized;
    assert.deepEqual(plainDiagnostics(unavailable), [{ backendId: "test.backend", code: "configuration_unavailable" }]);
  } finally { await unavailable.close(); }
});

test("[configuration-retry-atomic-routes] a retry installs complete routes in one step and never replays earlier events", async () => {
  const cfg = registration();
  cfg.hooks = ["first", "second"].map(name => ({ id: `test.${name}`, transport: { type: "http", url: `https://backend.test/${name}` } }));
  let available = false, release, firstDiscovered;
  const gate = new Promise(resolve => { release = resolve; });
  const firstDone = new Promise(resolve => { firstDiscovered = resolve; });
  const delivered = [], discoveries = {};
  const client = new Hooks(cfg, { ...options(async (url, init) => {
    const message = JSON.parse(init.body);
    const name = new URL(url).pathname.slice(1);
    if (message.method !== "hooks/configuration") { delivered.push([name, message.params.event.call.id]); return accepted(message); }
    if (!available) return new Response(null, { status: 503 });
    discoveries[name] = (discoveries[name] ?? 0) + 1;
    if (name === "second") await gate;
    const response = advertisement(message);
    if (name === "first") firstDiscovered();
    return response;
  }), configurationRetry: { initialDelayMs: 40, maxDelayMs: 40 } });
  try {
    await client.initialized;
    assert.equal(client.initializationDiagnostics.length, 2);
    await client.toolBefore({ ...input, callId: "before-retry" });
    available = true;
    await sleep(60);
    const concurrent = [client.toolBefore({ ...input, callId: "admitting" }), client.toolBefore({ ...input, callId: "concurrent" })];
    // The triggering and concurrent events never wait for the re-attempt.
    await Promise.all(concurrent);
    await firstDone;
    await sleep(10);
    // One backend's discovery finished, the other has not: no partial route set is visible.
    assert.equal(client.intercepts(events.toolBefore), false);
    await client.toolBefore({ ...input, callId: "during" });
    assert.deepEqual(delivered, []);
    release();
    await sleep(25);
    assert.equal(client.intercepts(events.toolBefore), true);
    await client.toolBefore({ ...input, callId: "after" });
    const order = delivered.filter(([, id]) => id === "after").map(([name]) => name);
    assert.deepEqual(order, ["first", "second"], "registration order is retained");
    assert.equal(delivered.length, 2, "events admitted before the retry succeeded are not replayed");
    assert.deepEqual(discoveries, { first: 1, second: 1 }, "concurrent admissions share one re-attempt per backend");
  } finally { await client.close(); }
});

test("a host prepare that arrives during an attempt is not lost", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  for (const phase of ["initialization", "re-attempt"]) {
    let attempts = 0, authorized = false, entered, release;
    const host = preparedProvider(async () => {
      attempts++;
      if (authorized) return undefined;
      if ((phase === "initialization" && attempts === 1) || (phase === "re-attempt" && attempts === 2)) {
        entered(); await new Promise(resolve => { release = resolve; });
      }
      throw new AuthError("interaction_required");
    });
    let started = new Promise(resolve => { entered = resolve; });
    const client = new Hooks(registration(), { ...options(async (_url, init) => advertisement(JSON.parse(init.body))), auth: host.provider });
    try {
      if (phase === "re-attempt") {
        await client.initialized;
        host.prepare(endpoint());
        const admitting = client.toolBefore(input);
        await started;
        host.prepare(endpoint());
        release();
        await admitting;
        await sleep(25);
        assert.equal(attempts, 2);
      } else {
        await started;
        host.prepare(endpoint());
        release();
        await client.initialized;
        assert.equal(attempts, 1);
      }
      // The attempt still failed, but the prepare made during it keeps the backend eligible.
      authorized = true;
      await admit(client);
      assert.equal(client.intercepts(events.toolBefore), true, phase);
    } finally { await client.close(); }
  }
});

test("closing during discovery closes transports of backends that were discovered but not installed", () => {
  // A child process reports and exits explicitly, so a leaked stdio backend fails
  // the assertion instead of keeping the test process alive.
  for (const phase of ["initialization", "re-attempt"]) {
    const run = spawnSync(process.execPath, [new URL("./fixtures/close-during-discovery.mjs", import.meta.url).pathname, phase],
      { encoding: "utf8", timeout: 20_000 });
    assert.equal(run.status, 0, `${phase}: ${run.stdout}${run.stderr}`);
    const report = JSON.parse(run.stdout.trim().split("\n").at(-1));
    assert.ok(report.spawned >= 1, phase);
    assert.equal(report.leaked, 0, `${phase}: every spawned backend is closed`);
  }
});

test("prepare matching compares normalized endpoint URLs", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  let authorized = false;
  const host = preparedProvider(() => { if (!authorized) throw new AuthError("interaction_required"); });
  const client = new Hooks(registration(), { ...options(async (_url, init) => advertisement(JSON.parse(init.body))), auth: host.provider });
  try {
    await client.initialized;
    authorized = true;
    host.prepare(endpoint("test.backend", "https://BACKEND.test:443/hooks"));
    await admit(client);
    assert.equal(client.intercepts(events.toolBefore), true);
  } finally { await client.close(); }
});

test("Hooks subscribes to prepare notifications only while a backend is unavailable", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  const explicit = preparedProvider();
  const fixed = new Hooks(registration(configuration().subscriptions), { ...options(), auth: explicit.provider });
  await fixed.initialized;
  assert.equal(explicit.listeners.size, 0, "explicit subscriptions never subscribe");
  const healthy = preparedProvider();
  const discovered = new Hooks(registration(), { ...options(async (_url, init) => advertisement(JSON.parse(init.body))), auth: healthy.provider });
  await discovered.initialized;
  assert.equal(healthy.listeners.size, 0, "successful discovery releases the subscription");
  let authorized = false;
  const host = preparedProvider(() => { if (!authorized) throw new AuthError("interaction_required"); });
  const client = new Hooks(registration(), { ...options(async (_url, init) => advertisement(JSON.parse(init.body))), auth: host.provider });
  try {
    await client.initialized;
    assert.equal(host.listeners.size, 1, "an unavailable backend keeps one subscription");
    authorized = true;
    host.prepare(endpoint());
    await admit(client);
    assert.equal(host.listeners.size, 0, "recovery releases the subscription");
  } finally { await Promise.all([client.close(), fixed.close(), discovered.close()]); }
});

test("stored skip diagnostics keep only the latest 10 per backend", async () => {
  const cfg = registration();
  cfg.hooks.push({ id: "test.other", transport: { type: "http", url: "https://backend.test/other" } });
  const client = new Hooks(cfg, { ...options(async () => new Response(null, { status: 503 })),
    configurationRetry: { initialDelayMs: 1, maxDelayMs: 1 } });
  try {
    await client.initialized;
    for (let i = 0; i < 14; i++) { await sleep(3); await client.toolBefore(input); }
    for (const id of ["test.backend", "test.other"])
      assert.equal(client.initializationDiagnostics.filter(diagnostic => diagnostic.backendId === id).length, 10, id);
  } finally { await client.close(); }
});

test("a hung re-attempt never holds delivery to other backends", async () => {
  const cfg = registration();
  cfg.hooks = [
    { id: "test.discovered", transport: { type: "http", url: "https://backend.test/discovered" } },
    { id: "test.enforced", transport: { type: "http", url: "https://backend.test/enforced" },
      subscriptions: [{ ...selected(), failurePolicy: "fail-closed" }] },
  ];
  let hang = false, discoveries = 0;
  const delivered = [];
  const client = new Hooks(cfg, { ...options(async (url, init) => {
    const message = JSON.parse(init.body);
    const name = new URL(url).pathname.slice(1);
    if (message.method === "hooks/configuration") {
      discoveries++;
      if (!hang) return new Response(null, { status: 503 });
      return new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason)));
    }
    delivered.push([name, message.params.event.call.id]);
    return accepted(message);
  }), configurationRetry: { initialDelayMs: 10, maxDelayMs: 10 } });
  try {
    await client.initialized;
    hang = true;
    await sleep(20);
    const started = Date.now();
    const triggering = await client.toolBefore({ ...input, callId: "triggering" }, { signal: AbortSignal.timeout(50) });
    const concurrent = await client.toolBefore({ ...input, callId: "concurrent" }, { signal: AbortSignal.timeout(50) });
    assert.ok(Date.now() - started < 1000, "events do not wait for the configuration budget");
    assert.equal(discoveries, 2, "the re-attempt is running in the background");
    assert.equal(triggering.interrupted, false);
    assert.equal(concurrent.interrupted, false);
    assert.deepEqual(delivered, [["enforced", "triggering"], ["enforced", "concurrent"]]);
  } finally { await client.close(); }
});

for (const lifecycle of ["persistent", "per_event"]) {
  test(`stdio ${lifecycle} discovery discards an id-mismatched frame and times out as unavailable`, async () => {
    const script = `require('node:readline').createInterface({ input: process.stdin }).on('line', line => {
      const request = JSON.parse(line);
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 'other-' + request.id, result: { protocolVersion: 'draft',
        configuration: ${JSON.stringify(configuration())} } }) + '\\n');
    });`;
    const cfg = registration();
    cfg.hooks[0].transport = { type: "stdio", command: process.execPath, args: ["-e", script], lifecycle };
    const client = new Hooks(cfg, { ...options(), configurationTimeoutMs: 1500 });
    try {
      await client.initialized;
      assert.deepEqual(plainDiagnostics(client), [{ backendId: "test.backend", code: "configuration_unavailable" }]);
    } finally { await client.close(); }
  });
}

test("HTTP discovery maps non-200 statuses to unavailable and 200 malformed or method-not-found to invalid", async () => {
  const { AuthError } = await import("agenthooksprotocol/client");
  const cases = [
    ["500", () => new Response(null, { status: 500 }), {}, { code: "configuration_unavailable" }],
    ["202", () => new Response(null, { status: 202 }), {}, { code: "configuration_unavailable" }],
    ["403", () => new Response(null, { status: 403, headers: { "www-authenticate": 'Bearer error="insufficient_scope", scope="admin"' } }),
      { auth: { credential() { return undefined; }, challenge() { throw new AuthError("access_denied"); } } },
      { code: "configuration_unavailable", authError: "access_denied", recovery: "none" }],
    ["200 non-JSON", () => new Response("not json", { status: 200, headers: { "content-type": "application/json" } }), {}, { code: "configuration_invalid" }],
    ["200 text/plain", () => new Response("{}", { status: 200, headers: { "content-type": "text/plain" } }), {}, { code: "configuration_invalid" }],
    ["200 method-not-found", message => Response.json({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } }), {}, { code: "configuration_invalid" }],
  ];
  for (const [label, respond, extra, expected] of cases) {
    const client = new Hooks(registration(), { ...options(async (_url, init) => respond(JSON.parse(init.body))), ...extra });
    try {
      await client.initialized;
      assert.deepEqual(plainDiagnostics(client), [{ backendId: "test.backend", ...expected }], label);
    } finally { await client.close(); }
  }
});
