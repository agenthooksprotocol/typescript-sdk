import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import {
  BackendTransport,
  Hooks,
  auth,
  Attachment,
} from "agenthooksprotocol/client";

const message = {
  jsonrpc: "2.0",
  id: 1,
  method: "hooks/intercept",
  params: {},
};
const reply = (init) =>
  Response.json({
    jsonrpc: "2.0",
    id: JSON.parse(init.body).id,
    result: { protocolVersion: "draft", effects: [] },
  });
function transport(
  headers,
  fetcher = async (_url, init) => reply(init),
  options = {},
  url = "https://example.com/events",
) {
  return new BackendTransport(
    {
      id: "headers.backend",
      subscriptions: [],
      transport: { type: "http", url, headers },
    },
    fetcher,
    options,
  );
}
function hooks(headers, fetcher, { timeoutMs = 10000, ...options } = {}) {
  return new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "headers.backend",
          transport: {
            type: "http",
            url: "https://example.com/events",
            headers,
          },
          subscriptions: [
            {
              mode: "intercept",
              events: ["tool.before"],
              timeoutMs,
              failurePolicy: "fail-closed",
              content: { default: "metadata" },
            },
          ],
        },
      ],
    },
    {
      source: "urn:test:headers",
      harness: { name: "test", version: "1" },
      capabilities: { toolBefore: { intercept: { deny: true } } },
      auth: { credential: () => undefined, challenge: () => false },
      fetch: fetcher,
      ...options,
    },
  );
}
test("custom event headers never enter OAuth discovery, issuer metadata or token exchange", async () => {
  const issuer = "https://identity.example.com";
  const resource = "https://example.com";
  const requests = [];
  let events = 0;
  let resolutions = 0;
  const provider = auth({
    resolveHostname: async () => ["93.184.216.34"],
    selectClient: () => ({
      type: "oauth",
      issuer,
      resource,
      clientId: "client",
      flow: "client_credentials",
    }),
    fetch: async (url, init = {}) => {
      requests.push(String(url));
      assert.equal(new Headers(init.headers).has("x-key"), false);
      if (String(url).includes("oauth-protected-resource"))
        return Response.json({ resource, authorization_servers: [issuer] });
      if (String(url).includes("well-known"))
        return Response.json({
          issuer,
          token_endpoint: `${issuer}/token`,
          grant_types_supported: ["client_credentials"],
          token_endpoint_auth_methods_supported: ["none"],
        });
      return Response.json({
        access_token: "oauth-secret",
        token_type: "Bearer",
        expires_in: 3600,
      });
    },
  });
  const h = hooks(
    { "X-Key": { valueRef: "key" } },
    async (_url, init) => {
      assert.equal(new Headers(init.headers).get("x-key"), "event-only");
      return ++events === 1 ? new Response(null, { status: 401 }) : reply(init);
    },
    {
      auth: provider,
      headerResolver: () => {
        resolutions++;
        return "event-only";
      },
    },
  );
  try {
    const result = await h.dispatch("tool.before", input());
    assert.deepEqual(
      result.diagnostics.filter((d) => d.phase !== "observation"),
      [],
    );
    assert.equal(events, 2);
    assert.equal(resolutions, 1);
    assert.ok(requests.some((url) => url.includes("oauth-protected-resource")));
    assert.ok(requests.includes(`${issuer}/token`));
  } finally {
    await h.close();
  }
});

test("same-origin uploads and another backend do not inherit event headers", async () => {
  const seen = [];
  const h = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [0, 1].map((i) => ({
        id: `test.backend${i}`,
        transport: {
          type: "http",
          url: `https://example.com/event-${i}`,
          ...(i === 0 ? { headers: { "X-Key": "event-zero-only" } } : {}),
        },
        subscriptions: [
          {
            mode: "intercept",
            events: ["turn.start"],
            timeoutMs: 1000,
            failurePolicy: "fail-closed",
            content: { default: "body" },
            upload: {
              endpoint: "https://example.com/upload",
              maxBytes: 1024,
              timeoutMs: 1000,
            },
          },
        ],
      })),
    },
    {
      source: "urn:test:headers",
      harness: { name: "test", version: "1" },
      capabilities: { turnStart: { intercept: { deny: true } } },
      auth: { credential: () => undefined, challenge: () => false },
      fetch: async (url, init) => {
        seen.push([url, new Headers(init.headers).get("x-key")]);
        if (url.endsWith("/upload"))
          return Response.json(
            {
              ref: "https://example.com/receipt",
              size: init.body.byteLength,
              sha256: createHash("sha256").update(init.body).digest("hex"),
            },
            { status: 201 },
          );
        return reply(init);
      },
    },
  );
  try {
    const result = await h.turnStart({
      turn: { id: "turn" },
      trigger: "user",
      items: [
        {
          role: "user",
          parts: [
            {
              kind: "attachment",
              mediaType: "application/octet-stream",
              selection: "body",
              body: Attachment.bytes(new Uint8Array([1, 2, 3])),
            },
          ],
        },
      ],
    });
    assert.deepEqual(
      result.diagnostics.filter((d) => d.phase !== "observation"),
      [],
    );
    assert.equal(seen.filter(([url]) => url.endsWith("/upload")).length, 2);
    for (const [url, value] of seen)
      assert.equal(value, url.endsWith("/event-0") ? "event-zero-only" : null);
    await result.content?.close();
  } finally {
    await h.close();
  }
});

const input = () => ({
  call: { id: "call" },
  path: "native",
  tool: { name: "test", origin: "native", input: {} },
});

test("literal and environment registration headers reach actual event POSTs, not redirects", async () => {
  const received = [];
  const server = createServer((req, res) => {
    received.push({ path: req.url, headers: req.headers, method: req.method });
    req.resume();
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "/leak" });
      res.end();
    } else {
      res.writeHead(204);
      res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  process.env.AHP_HEADERS_TEST = "first-secret";
  try {
    const t = transport(
      {
        "X-Tenant": "team",
        "X-Key": { valueEnv: "AHP_HEADERS_TEST" },
        "X-Empty": "",
      },
      fetch,
      {},
      `${url}/events`,
    );
    await t.notify({ ...message, method: "hooks/observe" });
    process.env.AHP_HEADERS_TEST = "rotated-secret";
    await t.notify({ ...message, method: "hooks/observe" });
    assert.equal(received[0].method, "POST");
    assert.equal(received[0].headers["x-tenant"], "team");
    assert.equal(received[0].headers["x-empty"], "");
    assert.equal(received[0].headers["x-key"], "first-secret");
    assert.equal(received[1].headers["x-key"], "rotated-secret");
    await assert.rejects(
      transport({ "X-Key": "secret" }, fetch, {}, `${url}/redirect`).notify({
        ...message,
        method: "hooks/observe",
      }),
    );
    assert.deepEqual(
      received.map((r) => r.path),
      ["/events", "/events", "/redirect"],
    );
    await t.close();
  } finally {
    delete process.env.AHP_HEADERS_TEST;
    await new Promise((resolve) => server.close(resolve));
  }
});

test("invalid names, reserved headers, duplicate names and invalid values fail before I/O", () => {
  const reserved = [
    "Authorization",
    "Proxy-X",
    "Cookie",
    "Set-Cookie",
    "Host",
    "Content-Type",
    "Accept",
    "Content-Length",
    "Content-Encoding",
    "Connection",
    "Keep-Alive",
    "Transfer-Encoding",
    "TE",
    "Trailer",
    "Upgrade",
    "Expect",
    "Origin",
    "Referer",
    "Sec-X",
    "AHP-X",
  ];
  const invalid = [
    null,
    [],
    { "X-Key": "a", "x-key": "a" },
    ...["", "bad name", "é", "x:\n"].map((n) => ({ [n]: "secret" })),
    ...reserved.flatMap((n) => [
      { [n]: "secret" },
      { [n.toUpperCase()]: "secret" },
    ]),
    ...[
      null,
      [],
      1,
      true,
      "\r",
      "\n",
      "\t",
      "\0",
      "\x7f",
      "é",
      {},
      { valueRef: "" },
      { valueEnv: "" },
      { valueEnv: "BAD-NAME" },
      { valueEnv: "A", valueRef: "B" },
      { valueRef: "A", extra: true },
    ].map((v) => ({ "X-Key": v })),
    { "X-Key": "a".repeat(16384) },
  ];
  for (const headers of invalid)
    assert.throws(
      () => transport(headers),
      /Invalid HTTP registration headers/,
    );
});

test("missing, invalid, and failed secret lookups fail closed without disclosing values", async () => {
  for (const value of [
    undefined,
    "",
    "secret\nvalue",
    "secret\tvalue",
    "é",
    42,
  ]) {
    let calls = 0;
    const t = transport(
      { "X-Key": { valueRef: "vault-key" } },
      async () => {
        calls++;
      },
      { headerResolver: () => value },
    );
    await assert.rejects(
      t.request(message),
      (error) => error.message === "HTTP registration header resolution failed",
    );
    assert.equal(calls, 0);
  }
  await assert.rejects(
    transport({ "X-Key": { valueRef: "unsupported" } }).request(message),
    /resolution failed/,
  );
  await assert.rejects(
    transport({ "X-Key": { valueEnv: "AHP_HEADERS_MISSING_TEST" } }).request(
      message,
    ),
    /resolution failed/,
  );
  await assert.rejects(
    transport({ "X-Key": { valueRef: "vault-key" } }, undefined, {
      headerResolver() {
        throw new Error("TOP SECRET");
      },
    }).request(message),
    (error) => !error.message.includes("TOP SECRET"),
  );
});

test("resolver context is endpoint-scoped and cancellation prevents late sends", async () => {
  let finish;
  let calls = 0;
  let context;
  const t = transport(
    { "X-Key": { valueRef: "vault-key" } },
    async () => {
      calls++;
    },
    {
      headerResolver(source, ctx) {
        assert.deepEqual(source, { valueRef: "vault-key" });
        context = ctx;
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    },
  );
  const controller = new AbortController();
  const request = t.request(message, controller.signal);
  assert.equal(context.backendId, "headers.backend");
  assert.equal(context.url, "https://example.com/events");
  assert.equal(context.purpose, "event");
  controller.abort(new Error("deadline"));
  await assert.rejects(request, /deadline/);
  assert.equal(context.signal.aborted, true);
  finish("late-secret");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 0);
});

test("caller mutation cannot retarget configured headers or replace source references", async () => {
  const config = {
    id: "headers.backend",
    subscriptions: [],
    transport: {
      type: "http",
      url: "https://example.com/original",
      headers: { "X-Key": { valueRef: "original" } },
    },
  };
  const seen = [];
  const t = new BackendTransport(
    config,
    async (url, init) => {
      seen.push(url);
      return reply(init);
    },
    {
      headerResolver(source) {
        assert.equal(source.valueRef, "original");
        source.valueRef = "resolver-mutation";
        return "resolved";
      },
    },
  );
  config.transport.url = "https://example.com/other";
  config.transport.headers["X-Key"].valueRef = "caller-mutation";
  await t.request(message);
  await t.request(message);
  assert.deepEqual(seen, [
    "https://example.com/original",
    "https://example.com/original",
  ]);
  await t.close();
});

test("headers do not reach non-event requests or another transport", async () => {
  const seen = [];
  const fetcher = async (_url, init) => {
    seen.push(new Headers(init.headers));
    return reply(init);
  };
  const t = transport({ "X-Key": "secret" }, fetcher);
  await t.request({ ...message, method: "hooks/capabilities" });
  await transport(undefined, fetcher).request(message);
  assert.equal(seen[0].has("x-key"), false);
  assert.equal(seen[1].has("x-key"), false);
});

test("Hooks resolves once per dispatch, preserves auth retries and rotates next dispatch", async () => {
  let resolutions = 0;
  let calls = 0;
  const seen = [];
  const h = hooks(
    { "X-Key": { valueRef: "key" } },
    async (_url, init) => {
      calls++;
      seen.push(new Headers(init.headers));
      assert.equal(init.redirect, "error");
      return calls === 1 ? new Response(null, { status: 401 }) : reply(init);
    },
    {
      headerResolver: () => `secret-${++resolutions}`,
      auth: {
        credential: () => ({ type: "bearer", token: "auth-only" }),
        challenge: () => true,
      },
    },
  );
  try {
    await h.initialized;
    await h.dispatch("tool.before", input());
    await h.dispatch("tool.before", input());
    assert.equal(calls, 3);
    assert.equal(resolutions, 2);
    assert.deepEqual(
      seen.map((h) => h.get("x-key")),
      ["secret-1", "secret-1", "secret-2"],
    );
    assert.ok(seen.every((h) => h.get("authorization") === "Bearer auth-only"));
  } finally {
    await h.close();
  }
});

test("Hooks rejects invalid static headers on initialization and bounds resolution by dispatch deadline", async () => {
  const invalid = hooks({ Authorization: "secret" }, () =>
    assert.fail("unexpected I/O"),
  );
  await assert.rejects(invalid.initialized);
  await invalid.close();
  const h = hooks(
    { "X-Key": { valueRef: "key" } },
    () => assert.fail("unexpected I/O"),
    {
      timeoutMs: 50,
      headerResolver: () => new Promise(() => {}),
    },
  );
  try {
    const result = await h.dispatch("tool.before", input());
    assert.ok(result.diagnostics.length > 0);
  } finally {
    await h.close();
  }
});
