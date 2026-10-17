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
    resolveCredentialReference() {
      resolutions++;
      return "event-only";
    },
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

test("backend uploads share configured headers without leaking to another backend", async () => {
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
              endpoint: `https://example.com/upload-${i}`,
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
        if (url.includes("/upload-"))
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
    assert.equal(seen.filter(([url]) => url.includes("/upload-")).length, 2);
    for (const [url, value] of seen)
      assert.equal(value, url.endsWith("-0") ? "event-zero-only" : null);
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

test("literal and environment headers reach event POSTs with unchanged redirect behavior", async () => {
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
        "X-Latin": "caf\u00e9",
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
    assert.equal(received[0].headers["x-latin"], "caf\u00e9");
    assert.equal(received[0].headers["x-empty"], "");
    assert.equal(received[0].headers["x-key"], "first-secret");
    assert.equal(received[1].headers["x-key"], "rotated-secret");
    for (const configured of [undefined, { "X-Key": "secret" }]) {
      await assert.rejects(
        transport(configured, fetch, {}, `${url}/redirect`).notify({
          ...message,
          method: "hooks/observe",
        }),
      );
    }
    assert.deepEqual(
      received.map((r) => r.path),
      ["/events", "/events", "/redirect", "/redirect"],
    );
    await t.close();
  } finally {
    delete process.env.AHP_HEADERS_TEST;
    await new Promise((resolve) => server.close(resolve));
  }
});

for (const source of [
  "Bearer abc123",
  { valueRef: "authorization" },
  { valueEnv: "HEADER_AUTH" },
]) {
  test(`explicit Authorization suppresses credential acquisition and 401 retry (${JSON.stringify(source)})`, async () => {
    let calls = 0;
    const h = hooks(
      {
        Authorization: { valueRef: "losing-source-never-resolved" },
        AUTHORIZATION: source,
        "Content-Type": "custom/type",
        Cookie: "literal-secret",
      },
      async (_url, init) => {
        calls++;
        const headers = new Headers(init.headers);
        assert.equal(headers.get("authorization"), "Bearer abc123");
        assert.equal(headers.get("content-type"), "custom/type");
        assert.equal(headers.get("cookie"), "literal-secret");
        return new Response(null, { status: 401 });
      },
      {
        auth: auth({
          resolveCredentialReference: (reference) => {
            assert.equal(reference, "authorization");
            return "Bearer abc123";
          },
          resolveEnvironmentVariable: () => "Bearer abc123",
          credential() {
            assert.fail("explicit Authorization must suppress acquisition");
          },
          challenge() {
            assert.fail("explicit Authorization must suppress challenge");
          },
          fetch() {
            assert.fail(
              "explicit Authorization must suppress discovery/token I/O",
            );
          },
        }),
      },
    );
    try {
      await h.dispatch("tool.before", input());
      assert.equal(calls, 1);
    } finally {
      await h.close();
    }
  });
}

test("missing explicit Authorization fails rather than falling back to auth", async () => {
  const h = hooks(
    { Authorization: { valueRef: "missing" } },
    () => assert.fail("unexpected network request"),
    {
      auth: {
        resolveCredentialReference: () => undefined,
        credential() {
          assert.fail("no fallback");
        },
        challenge() {
          assert.fail("no challenge");
        },
      },
    },
  );
  try {
    const result = await h.dispatch("tool.before", input());
    assert.ok(result.diagnostics.length > 0);
  } finally {
    await h.close();
  }
});

for (const uploadStatus of [201, 401]) {
  test(`actual upload headers override defaults/auth and suppress OAuth (${uploadStatus})`, async () => {
    const received = [];
    const contexts = [];
    const server = createServer(async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      received.push({ path: req.url, headers: req.headers });
      if (req.url === "/upload" && uploadStatus === 201) {
        res.writeHead(201, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            ref: "urn:test:uploaded",
            size: body.length,
            sha256: createHash("sha256").update(body).digest("hex"),
          }),
        );
      } else {
        res.writeHead(401);
        res.end();
      }
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const h = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "test.upload",
            authentication: { type: "bearer", tokenRef: "must-not-resolve" },
            transport: {
              type: "http",
              url: `${base}/events`,
              headers: {
                Authorization: { valueRef: "configured-auth" },
                Cookie: "session=literal",
                "X-Api-Key": "literal-api-key",
                "Content-Type": "application/custom",
              },
            },
            subscriptions: [
              {
                mode: "intercept",
                events: ["turn.start"],
                timeoutMs: 10000,
                failurePolicy: "fail-closed",
                content: { default: "body" },
                upload: {
                  endpoint: `${base}/upload`,
                  maxBytes: 1024,
                  timeoutMs: 10000,
                  auth: { type: "bearer", tokenRef: "upload-must-not-resolve" },
                },
              },
            ],
          },
        ],
      },
      {
        source: "urn:test:headers",
        harness: { name: "test", version: "1" },
        capabilities: { turnStart: { intercept: { deny: true } } },
        auth: auth({
          resolveCredentialReference(reference, context) {
            assert.equal(reference, "configured-auth");
            contexts.push(context);
            return "Bearer abc123";
          },
          credential() {
            assert.fail("no credential acquisition for upload or event");
          },
          challenge() {
            assert.fail("no challenge for explicit Authorization");
          },
          fetch() {
            assert.fail("no discovery or token requests");
          },
        }),
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
      assert.ok(received.some((r) => r.path === "/upload"));
      assert.equal(received.filter((r) => r.path === "/upload").length, 1);
      assert.equal(
        received.filter((r) => r.path === "/events").length,
        uploadStatus === 201 ? 1 : 0,
      );
      for (const { headers } of received) {
        assert.equal(headers.authorization, "Bearer abc123");
        assert.equal(headers.cookie, "session=literal");
        assert.equal(headers["x-api-key"], "literal-api-key");
        assert.equal(headers["content-type"], "application/custom");
      }
      assert.equal(contexts[0].purpose, "upload");
      assert.equal(contexts[0].url, `${base}/upload`);
      assert.equal(contexts[0].backendId, "test.upload");
      assert.ok(contexts[0].signal instanceof AbortSignal);
      await result.content?.close();
    } finally {
      await h.close();
      await new Promise((resolve) => server.close(resolve));
    }
  });
}

test("native HTTP rejects invalid syntax and injection without extra policy", async () => {
  for (const headers of [
    null,
    [],
    { "bad name": "value" },
    { "X-Key": "bad\r\nvalue" },
    { "X-Key": "bad\0value" },
    { "X-Key": [] },
    { "X-Key": { valueRef: "" } },
    { "X-Key": { valueEnv: "A", valueRef: "B" } },
  ])
    assert.throws(
      () => transport(headers),
      /Invalid HTTP registration headers/,
    );
  const seen = [];
  const t = transport(
    {
      Authorization: "Bearer abc123",
      Cookie: "session=secret",
      Origin: "https://example.com",
      "Content-Type": "custom/type",
      "X-Key": "literal-api-key",
      "x-key": "last",
      "X-Latin": "caf\u00e9",
      "X-Tab": "a\tb",
      "AHP-Version": "custom",
      "X-Large": "x".repeat(17000),
    },
    async (_url, init) => {
      seen.push(new Headers(init.headers));
      return reply(init);
    },
  );
  await t.request(message);
  assert.equal(seen[0].get("authorization"), "Bearer abc123");
  assert.equal(seen[0].get("cookie"), "session=secret");
  assert.equal(seen[0].get("content-type"), "custom/type");
  assert.equal(seen[0].get("x-key"), "last");
  assert.equal(seen[0].get("x-latin"), "caf\u00e9");
  assert.equal(seen[0].get("x-tab"), "a\tb");
  assert.equal(seen[0].get("x-large").length, 17000);
  await t.close();
});

test("missing, invalid, and failed secret lookups fail closed without disclosing values", async () => {
  for (const value of [undefined, "", "secret\nvalue", 42]) {
    let calls = 0;
    const t = transport(
      { "X-Key": { valueRef: "vault-key" } },
      async () => {
        calls++;
      },
      { auth: { resolveCredentialReference: () => value } },
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
      auth: {
        resolveCredentialReference() {
          throw new Error("TOP SECRET");
        },
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
      auth: {
        resolveCredentialReference(source, ctx) {
          assert.equal(source, "vault-key");
          context = ctx;
          return new Promise((resolve) => {
            finish = resolve;
          });
        },
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
      auth: {
        resolveCredentialReference(source) {
          assert.equal(source, "original");
          return "resolved";
        },
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

test("recognized source extensions remain inert and never reach the resolver", async () => {
  let sources = [];
  const t = transport(
    { "X-Key": { valueRef: "key", future: "opaque" } },
    undefined,
    {
      auth: {
        resolveCredentialReference(source) {
          sources.push(source);
          return "resolved";
        },
      },
    },
  );
  await t.request(message);
  assert.deepEqual(sources, ["key"]);
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
      auth: {
        resolveCredentialReference: () => `secret-${++resolutions}`,
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
  const invalid = hooks({ "bad name": "secret" }, () =>
    assert.fail("unexpected I/O"),
  );
  await assert.rejects(invalid.initialized);
  await invalid.close();
  const h = hooks(
    { "X-Key": { valueRef: "key" } },
    () => assert.fail("unexpected I/O"),
    {
      timeoutMs: 50,
      auth: {
        credential: () => undefined,
        challenge() {},
        resolveCredentialReference: () => new Promise(() => {}),
      },
    },
  );
  try {
    const result = await h.dispatch("tool.before", input());
    assert.ok(result.diagnostics.length > 0);
  } finally {
    await h.close();
  }
});
