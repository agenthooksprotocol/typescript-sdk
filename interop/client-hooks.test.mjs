import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks, auth, ConfigurationError } = await import(
  require.resolve("agenthooksprotocol/client")
);

const { hooks: serverHooks, attachments } = await import(
  require.resolve("agenthooksprotocol/server")
);

const caps = {
  effects: [
    "deny",
    "modify",
    "return",
    "allow",
    "ask",
    "message",
    "flow",
    "inject",
  ],
  modify: { input: { replace: true, merge: true } },
  flow: { operations: ["stop"] },
  inject: { context: { append: true, deliverAt: ["now", "next_turn"] } },
};
const tool = () => ({
  call: { id: "call" },
  path: "native",
  tool: { name: "test", origin: "native", input: { x: 1 } },
});
const sub = (extra = {}) => ({
  mode: "intercept",
  events: ["tool.before"],
  // Real receiver schema compilation can contend with other test files.
  // Deadline/cancellation fixtures override this normal-success budget below.
  timeoutMs: 10000,
  failurePolicy: "fail-open",
  content: { default: "metadata" },
  ...extra,
});
const config = (url, subscriptions = [sub()], extra = {}) => ({
  protocolVersion: "draft",
  hooks: [
    {
      id: "test.backend",
      transport: { type: "http", url },
      subscriptions,
      ...extra,
    },
  ],
});
const options = (extra) => ({
  source: "urn:test:harness",
  capabilities: {
    "tool.before": { modes: ["intercept", "observe"], capabilities: caps },
  },
  ...extra,
});
async function server(run) {
  const messages = [];
  const s = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    req.rawBody = Buffer.concat(chunks);
    const body = req.rawBody.toString("utf8");
    let message;
    try {
      message = JSON.parse(body);
    } catch {
      message = body;
    }
    messages.push({ message, headers: req.headers, url: req.url });
    try {
      await run(message, req, res, messages.length);
    } catch {
      res.writeHead(500).end();
    }
  });
  await new Promise((resolve) => s.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${s.address().port}`,
    messages,
    close: () =>
      new Promise((resolve) => {
        s.close(resolve);
        s.closeAllConnections();
      }),
  };
}
// Deliberately bypass server validation for malformed/unsupported wire fixtures.
const rawReply = (res, request, effects = []) =>
  res.writeHead(200, { "content-type": "application/json" }).end(
    JSON.stringify({
      jsonrpc: "2.0",
      id: request.id,
      result: { protocolVersion: "draft", effects },
    }),
  );
async function send(res, response) {
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(new Uint8Array(await response.arrayBuffer()));
}
const reply = async (res, message, effects = []) =>
  send(
    res,
    await serverHooks.handle(
      new Request("http://receiver.test/hooks", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(message),
      }),
      () => ({ effects }),
    ),
  );
async function uploadReply(req, res, store) {
  const upload = attachments.parse(
    new Request(`http://receiver.test${req.url}`, {
      method: req.method,
      headers: req.headers,
      body: req.rawBody,
    }),
  );
  const bytes = Buffer.from(await new Response(upload.body).arrayBuffer());
  const ref = await store(bytes);
  await send(
    res,
    attachments.response({ ref, size: upload.size, sha256: upload.sha256 }),
  );
}
const until = async (f) => {
  for (let i = 0; i < 100; i++) {
    if (f()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.ok(f(), "condition timed out");
};

test("public Hooks initializes, fans out stable identities, and returns accepted canonical effects", async () => {
  const s = await server((m, req, res, n) =>
    reply(
      res,
      m,
      n === 1
        ? [
            {
              type: "modify",
              target: "input",
              operation: "merge",
              value: { x: 2 },
            },
            { type: "return", value: "cached" },
            { type: "allow" },
          ]
        : [
            {
              type: "modify",
              target: "input",
              operation: "replace",
              value: { x: 3 },
            },
            { type: "message", text: "accepted" },
          ],
    ),
  );
  const hooks = new Hooks(config(s.url, [sub(), sub()]), options());
  try {
    const result = await hooks.dispatch("tool.before", tool());
    assert.deepEqual(result.event.tool.input, { x: 3 });
    assert.equal(result.errors.length, 0);
    assert.deepEqual(
      result.response.result.effects.map((e) => e.type),
      ["modify", "modify", "message"],
    );
    assert.equal(s.messages[0].message.id, s.messages[1].message.id);
    assert.equal(
      s.messages[0].message.params.event.id,
      s.messages[1].message.params.event.id,
    );
    assert.equal(s.messages[1].message.params.state.candidate.value, "cached");
    assert.deepEqual(s.messages[1].message.params.event.tool.input, { x: 2 });
    assert.equal(result.event.source, "urn:test:harness");
    assert.equal(typeof result.event.id, "string");
    const first = hooks.close();
    assert.equal(first, hooks.close());
    await first;
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("compound response rejects atomically once, then fail-closed observes uncalled interceptors", async () => {
  const s = await server((m, req, res) =>
    m.method === "hooks/observe"
      ? reply(res, m)
      : rawReply(res, m, [
          {
            type: "modify",
            target: "input",
            operation: "merge",
            value: { secret: "discard" },
          },
          { type: "unknown" },
        ]),
  );
  const hooks = new Hooks(
    config(s.url, [
      sub({ failurePolicy: "fail-closed" }),
      sub(),
      { mode: "observe", events: ["*"], content: { default: "metadata" } },
    ]),
    options(),
  );
  try {
    const r = await hooks.dispatch("tool.before", tool());
    assert.equal(r.errors.length, 1);
    assert.equal(r.errors[0].syntheticDenial, true);
    assert.deepEqual(r.event.tool.input, { x: 1 });
    assert.equal(r.response.result.effects[0].type, "deny");
    await until(() => s.messages.length === 3);
    assert.deepEqual(
      s.messages.map((x) => x.message.method),
      ["hooks/intercept", "hooks/observe", "hooks/observe"],
    );
    assert.ok(
      s.messages
        .slice(1)
        .every((x) => x.message.params.event.tool.input.secret === undefined),
    );
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("dispatch authentication failure honors fail-open without unauthenticated fallback", async () => {
  const s = await server((m, q, r) => reply(r, m));
  const provider = auth({
    authenticate: async () => {
      throw new Error("secret must not appear");
    },
  });
  const hooks = new Hooks(
    config(s.url, [sub(), sub({ failurePolicy: "fail-closed" })]),
    options({ auth: provider }),
  );
  try {
    const r = await hooks.dispatch("tool.before", tool());
    assert.equal(s.messages.length, 0);
    assert.equal(r.errors.length, 2);
    assert.equal(r.errors[0].syntheticDenial, false);
    assert.equal(r.errors[1].syntheticDenial, true);
    assert.ok(!JSON.stringify(r).includes("secret must"));
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("top-level authentication override can ignore challenge; retry preserves body and identity", async () => {
  let calls = 0;
  const s = await server((m, q, r, n) =>
    n === 1
      ? r
          .writeHead(401, { "www-authenticate": 'Bearer nonsense="ignored"' })
          .end()
      : reply(r, m),
  );
  const hooks = new Hooks(
    config(s.url),
    options({
      auth: auth({ authenticate: async () => ({ token: `local-${++calls}` }) }),
    }),
  );
  try {
    const r = await hooks.dispatch("tool.before", tool());
    assert.equal(r.errors.length, 0);
    assert.equal(calls, 2);
    assert.deepEqual(s.messages[0].message, s.messages[1].message);
    assert.equal(s.messages[1].headers.authorization, "Bearer local-2");
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("deadline bounds even an authentication override that ignores its signal", async () => {
  const hooks = new Hooks(
    config("http://127.0.0.1:1", [
      sub({ timeoutMs: 25, failurePolicy: "fail-closed" }),
    ]),
    options({ auth: auth({ authenticate: () => new Promise(() => {}) }) }),
  );
  try {
    const start = Date.now();
    const r = await hooks.dispatch("tool.before", tool());
    assert.ok(Date.now() - start < 1000);
    assert.equal(r.errors[0].code, "DEADLINE_EXCEEDED");
    assert.equal(r.response.result.effects[0].type, "deny");
  } finally {
    await hooks.close();
  }
});

test("cancellation overrides fail-closed and close cancels pending work", async () => {
  let entered;
  const waiting = new Promise((r) => (entered = r));
  const hooks = new Hooks(
    config("http://127.0.0.1:1", [
      sub({ timeoutMs: 10000, failurePolicy: "fail-closed" }),
    ]),
    options({
      auth: auth({
        authenticate: () => {
          entered();
          return new Promise(() => {});
        },
      }),
    }),
  );
  const work = hooks.dispatch("tool.before", tool());
  await waiting;
  await hooks.close();
  const result = await work;
  assert.equal(result.interrupted, true);
  assert.equal(result.errors[0].syntheticDenial, false);
  await assert.rejects(hooks.dispatch("tool.before", tool()));
});

test("configuration errors are structured and observable by initialized or any boundary", async () => {
  const hooks = new Hooks({ protocolVersion: "draft", hooks: [] }, options());
  await assert.rejects(
    hooks.initialized,
    (e) =>
      e instanceof ConfigurationError &&
      e.code === "INVALID_CONFIGURATION" &&
      e.issues.length > 0,
  );
  await assert.rejects(
    hooks.dispatch("tool.before", tool()),
    ConfigurationError,
  );
  await hooks.close();
});

test("metadata observations do not consume bodies and native is opt-in", async () => {
  const s = await server((m, q, r) => reply(r, m));
  let reads = 0,
    canceled = false;
  const body = new ReadableStream(
    {
      pull() {
        reads++;
      },
      cancel() {
        canceled = true;
      },
    },
    { highWaterMark: 0 },
  );
  const hooks = new Hooks(
    config(s.url, [
      { mode: "observe", events: ["tool.*"], content: { default: "metadata" } },
    ]),
    options({ capabilities: { "tool.before": { modes: ["observe"] } } }),
  );
  try {
    const input = tool();
    input.items = [
      { id: "item", kind: "message", mediaType: "text/plain", body },
    ];
    input.native = {
      provider: "test",
      eventName: "native",
      payload: { hidden: true },
    };
    await hooks.dispatch("tool.before", input);
    await until(() => s.messages.length === 1);
    assert.equal(reads, 0);
    assert.equal(s.messages[0].message.params.event.native, undefined);
    assert.equal(
      s.messages[0].message.params.event.items[0].selection,
      "metadata",
    );
    await until(() => canceled);
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("uploads consume one raw snapshot, authenticate separately, and finish before each receiver event", async () => {
  const bytes = new TextEncoder().encode("immutable");
  let reads = 0;
  const seen = [];
  const stored = new Map();
  const credentials = [];
  const s = await server(async (m, q, r) => {
    seen.push(q.url);
    if (q.url.startsWith("/upload")) {
      await new Promise((r) => setTimeout(r, 40));
      await uploadReply(q, r, (bytes) => {
        stored.set(q.url, bytes);
        return q.url;
      });
    } else await reply(r, m);
  });
  const body = new ReadableStream(
    {
      pull(c) {
        reads++;
        c.enqueue(bytes);
        c.close();
      },
    },
    { highWaterMark: 0 },
  );
  const subscriptions = ["a", "b"].map((id) =>
    sub({
      timeoutMs: 30,
      content: { default: "body" },
      upload: {
        endpoint: `${s.url}/upload-${id}`,
        timeoutMs: 1000,
        maxBytes: 100,
        auth: { type: "bearer", tokenRef: `upload-${id}` },
      },
    }),
  );
  const provider = auth({
    resolveCredentialReference(ref) {
      credentials.push(ref);
      return ref;
    },
  });
  const hooks = new Hooks(
    config(s.url + "/event", subscriptions, {
      authentication: { type: "bearer", tokenRef: "event" },
    }),
    options({ auth: provider }),
  );
  try {
    const input = tool();
    input.items = [
      { id: "same-item", kind: "text", mediaType: "text/plain", body },
    ];
    const r = await hooks.dispatch("tool.before", input);
    assert.equal(r.errors.length, 0);
    assert.equal(reads, 1);
    assert.deepEqual(seen, ["/upload-a", "/event", "/upload-b", "/event"]);
    assert.deepEqual(credentials, ["upload-a", "event", "upload-b", "event"]);
    assert.deepEqual(stored.get("/upload-a"), Buffer.from(bytes));
    assert.deepEqual(stored.get("/upload-b"), Buffer.from(bytes));
    assert.equal(
      s.messages[1].message.params.event.items[0].body.ref,
      "/upload-a",
    );
    assert.equal(
      s.messages[3].message.params.event.items[0].body.ref,
      "/upload-b",
    );
    assert.equal(s.messages[1].headers.authorization, "Bearer event");
    assert.equal(s.messages[0].headers.authorization, "Bearer upload-a");
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("observation failures are available when the boundary call settles", async () => {
  const s = await server((m, q, r) => r.writeHead(503).end());
  const hooks = new Hooks(
    config(s.url, [
      { mode: "observe", events: ["tool.*"], content: { default: "metadata" } },
    ]),
    options({ capabilities: { "tool.before": { modes: ["observe"] } } }),
  );
  try {
    const r = await hooks.dispatch("tool.before", tool());
    assert.equal(r.errors.length, 0);
    const errors = await r.observations;
    assert.equal(errors.length, 1);
    assert.equal(errors[0].phase, "observation");
    assert.equal(errors[0].syntheticDenial, false);
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("invalid and expired override credentials fail before a network request", async () => {
  for (const credential of [
    { token: "invalid\r\nheader" },
    { token: "expired", expiresAt: 0 },
  ]) {
    const s = await server((m, q, r) => reply(r, m));
    const hooks = new Hooks(
      config(s.url),
      options({ auth: auth({ authenticate: async () => credential }) }),
    );
    try {
      const r = await hooks.dispatch("tool.before", tool());
      assert.equal(r.errors.length, 1);
      assert.equal(s.messages.length, 0);
    } finally {
      await hooks.close();
      await s.close();
    }
  }
});

const streamItem = (id, value) => {
  const bytes = new TextEncoder().encode(
    typeof value === "string" ? value : JSON.stringify(value),
  );
  return {
    id,
    kind: "text",
    mediaType: typeof value === "string" ? "text/plain" : "application/json",
    body: new ReadableStream({
      start(c) {
        c.enqueue(bytes);
        c.close();
      },
    }),
  };
};

test("elicitation retains authorized request schema and rewrites result bodies before downstream upload", async () => {
  const uploaded = [];
  const invocations = {};
  const s = await server((m, q, r) => {
    if (q.url === "/upload") {
      return uploadReply(q, r, (bytes) => {
        uploaded.push(bytes.toString());
        return `ref-${uploaded.length}`;
      });
    }
    const type = m.params.event.type;
    invocations[type] = (invocations[type] ?? 0) + 1;
    return reply(
      r,
      m,
      invocations[type] === 1
        ? type === "user.elicitation.request"
          ? [
              {
                type: "return",
                value: { action: "accept", content: { name: "Alice", age: 3 } },
              },
            ]
          : [
              {
                type: "modify",
                target: "content",
                operation: "merge",
                value: { age: 4 },
              },
            ]
        : [],
    );
  });
  const upload = {
    endpoint: s.url + "/upload",
    timeoutMs: 1000,
    maxBytes: 4096,
  };
  const subscriptions = [
    sub({
      events: ["user.*"],
      content: { default: "body" },
      upload,
    }),
    sub({
      events: ["user.*"],
      content: { default: "body" },
      upload,
    }),
  ];
  const hooks = new Hooks(
    config(s.url, subscriptions),
    options({
      capabilities: {
        "user.elicitation.request": {
          effects: ["return", "deny"],
          elicitation: { form: {} },
        },
        "user.elicitation.result": {
          effects: ["modify"],
          modify: { content: { merge: true, replace: true } },
          elicitation: { form: {} },
        },
      },
    }),
  );
  try {
    const request = await hooks.dispatch("user.elicitation.request", {
      session: { id: "session" },
      elicitation: {
        server: "mcp",
        mode: "form",
        request: streamItem("question", {
          message: "Name?",
          requestedSchema: {
            type: "object",
            properties: {
              name: { type: "string", minLength: 2 },
              age: { type: "integer" },
            },
            required: ["name"],
          },
        }),
      },
    });
    assert.equal(request.errors.length, 0);
    assert.equal(
      request.response.result.effects[0].value.content.name,
      "Alice",
    );
    const result = await hooks.dispatch("user.elicitation.result", {
      session: { id: "session" },
      parentEventId: request.event.id,
      elicitation: {
        server: "mcp",
        mode: "form",
        action: "accept",
        result: streamItem("answer", {
          action: "accept",
          content: { name: "Alice", age: 3 },
          _meta: { keep: true },
        }),
      },
    });
    assert.equal(result.errors.length, 0);
    assert.equal(result.event.elicitation.result.id, "answer");
    assert.deepEqual(JSON.parse(uploaded.at(-1)), {
      action: "accept",
      content: { name: "Alice", age: 4 },
      _meta: { keep: true },
    });
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("compaction rewrites body snapshots for later subscribers, and canonical continuation stays one step", async () => {
  const uploads = [];
  let count = 0;
  const s = await server((m, q, r) => {
    if (q.url === "/upload") {
      return uploadReply(q, r, (bytes) => {
        uploads.push(bytes.toString());
        return `ref-${uploads.length}`;
      });
    }
    if (m.params.event.type === "context.compact.before")
      return reply(
        r,
        m,
        ++count === 1
          ? [
              {
                type: "modify",
                target: "instructions",
                operation: "replace",
                value: "replacement",
              },
              { type: "return", value: "summary" },
            ]
          : [],
      );
    else
      return reply(r, m, [
        { type: "flow", operation: "continue", instruction: `step-${++count}` },
      ]);
  });
  const upload = {
    endpoint: s.url + "/upload",
    timeoutMs: 1000,
    maxBytes: 4096,
  };
  const subscriptions = [
    sub({
      events: ["context.compact.before", "turn.finish.before"],
      content: { default: "body" },
      upload,
    }),
    sub({
      events: ["context.compact.before", "turn.finish.before"],
      content: { default: "body" },
      upload,
    }),
  ];
  const hooks = new Hooks(
    config(s.url, subscriptions),
    options({
      capabilities: {
        "context.compact.before": {
          effects: ["modify", "return"],
          modify: { instructions: { replace: true, merge: false } },
        },
        "turn.finish.before": {
          effects: ["flow"],
          flow: {
            operations: ["continue", "stop"],
            remainingContinuations: 1,
            maxContinuations: 1,
            continuationCount: 0,
          },
        },
      },
    }),
  );
  try {
    const result = await hooks.dispatch("context.compact.before", {
      trigger: "manual",
      items: [],
      instructions: streamItem("instructions", "original"),
    });
    assert.equal(result.errors.length, 0);
    assert.deepEqual(uploads, ["original", "replacement"]);
    assert.equal(result.event.instructions.id, "instructions");
    const finish = await hooks.dispatch("turn.finish.before", {
      turn: { id: "turn" },
      outcome: "completed",
      continuationCount: 0,
      items: [],
    });
    assert.equal(finish.errors.length, 0);
    assert.equal(finish.response.result.effects.length, 2);
    const last = s.messages.at(-1).message;
    assert.equal(last.params.state.flow, "continue");
    assert.equal(last.params.state.instructions.length, 1);
  } finally {
    await hooks.close();
    await s.close();
  }
});

test("no-auth override cannot bypass an explicit binding or retry a challenge anonymously", async () => {
  for (const explicit of [true, false]) {
    const s = await server((m, q, r) =>
      r.writeHead(401, { "www-authenticate": "Bearer" }).end(),
    );
    const hooks = new Hooks(
      config(
        s.url,
        [sub({ failurePolicy: "fail-closed" })],
        explicit
          ? { authentication: { type: "bearer", tokenRef: "required" } }
          : {},
      ),
      options({ auth: auth({ authenticate: async () => undefined }) }),
    );
    try {
      const r = await hooks.dispatch("tool.before", tool());
      assert.equal(r.errors.length, 1);
      assert.equal(r.errors[0].syntheticDenial, true);
      assert.equal(s.messages.length, explicit ? 0 : 1);
    } finally {
      await hooks.close();
      await s.close();
    }
  }
});

test("capability narrowing ignores opaque extensions but rejects known expansions", async () => {
  const advertised = {
    ...caps,
    modify: { input: { replace: true, merge: false, futureHint: { old: 1 } } },
    flow: {
      operations: ["stop"],
      maxContinuations: 2,
      remainingContinuations: 1,
      continuationCount: 1,
    },
    futureHint: { old: true },
  };
  const s = await server((m, q, r) => reply(r, m));
  const hooks = new Hooks(
    config(s.url),
    options({ capabilities: { "tool.before": advertised } }),
  );
  try {
    const accepted = await hooks.dispatch("tool.before", tool(), {
      capabilities: {
        effects: caps.effects,
        futureHint: { different: true },
        modify: {
          input: { replace: true, merge: false, futureHint: { new: 2 } },
        },
        flow: { operations: ["stop"], futureHint: [1, 2] },
        inject: {
          context: { append: true, deliverAt: ["now"], futureHint: true },
          futureHint: true,
        },
      },
    });
    assert.deepEqual(accepted.errors, []);
    for (const expansion of [
      { effects: [...caps.effects, "futureEffect"] },
      { modify: { input: { replace: true, merge: true } } },
      { modify: { output: { replace: true, merge: false } } },
      { flow: { operations: ["stop", "continue"] } },
      { flow: { operations: ["stop"], maxContinuations: 3 } },
      { flow: { operations: ["stop"], remainingContinuations: 2 } },
      { flow: { operations: ["stop"], continuationCount: 0 } },
      { elicitation: { url: {} } },
    ])
      await assert.rejects(
        hooks.dispatch("tool.before", tool(), {
          capabilities: { effects: caps.effects, ...expansion },
        }),
        ConfigurationError,
      );
  } finally {
    await hooks.close();
    await s.close();
  }
});

for (const failure of ["timeout", "auth", "malformed"]) {
  test(`synthetic denial clears prior allow and candidate after ${failure}`, async () => {
    const s = await server((m, q, r, n) => {
      if (n === 1)
        return reply(r, m, [
          { type: "allow" },
          { type: "return", value: "cached" },
        ]);
      else if (failure === "malformed") r.writeHead(200).end("{");
    });
    let authentications = 0;
    const hooks = new Hooks(
      config(s.url, [
        sub(),
        sub({ timeoutMs: 50, failurePolicy: "fail-closed" }),
      ]),
      options({
        capabilities: { "tool.before": { effects: ["allow", "return"] } },
        ...(failure === "auth"
          ? {
              auth: auth({
                authenticate: async () => {
                  if (++authentications === 2) throw new Error("unavailable");
                  return { token: "local" };
                },
              }),
            }
          : {}),
      }),
    );
    try {
      const result = await hooks.dispatch("tool.before", tool());
      assert.deepEqual(result.response.result.effects, [
        { type: "deny", reason: "Required policy backend unavailable." },
      ]);
      assert.equal(result.errors.length, 1);
      assert.equal(result.errors[0].subscriptionIndex, 1);
      assert.equal(result.errors[0].syntheticDenial, true);
      assert.equal(s.messages[0].message.method, "hooks/intercept");
      if (failure !== "auth") {
        assert.equal(s.messages[1].message.params.state.permission, "allow");
        assert.deepEqual(s.messages[1].message.params.state.candidate, {
          value: "cached",
        });
      }
    } finally {
      await hooks.close();
      await s.close();
    }
  });
}

for (const exit of [
  "process.exit(0)",
  "process.exit(7)",
  "process.kill(process.pid, 'SIGTERM')",
]) {
  test(`per-event observation reports process outcome: ${exit}`, async () => {
    const hooks = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "test.backend",
            transport: {
              type: "stdio",
              command: process.execPath,
              args: [
                "-e",
                `process.stdin.resume(); process.stdin.on('end', () => { ${exit}; });`,
              ],
              lifecycle: "per_event",
            },
            subscriptions: [
              {
                mode: "observe",
                events: ["tool.before"],
                content: { default: "metadata" },
              },
            ],
          },
        ],
      },
      options(),
    );
    try {
      const result = await hooks.dispatch("tool.before", tool());
      assert.deepEqual(result.response.result.effects, []);
      assert.deepEqual(result.errors, []);
      const errors = await result.observations;
      if (exit === "process.exit(0)") assert.deepEqual(errors, []);
      else
        assert.deepEqual(errors, [
          {
            backendId: "test.backend",
            subscriptionIndex: 0,
            phase: "observation",
            code: "DELIVERY_FAILED",
            syntheticDenial: false,
          },
        ]);
    } finally {
      await hooks.close();
    }
  });
}

test("caller cancellation interrupts observations within the pending boundary call", async () => {
  let entered;
  const waiting = new Promise((resolve) => {
    entered = resolve;
  });
  let releaseAuthentication;
  const authentication = new Promise((resolve) => {
    releaseAuthentication = () => resolve({ token: "late-token" });
  });
  let requests = 0;
  const controller = new AbortController();
  const hooks = new Hooks(
    config("http://127.0.0.1:1", [
      {
        mode: "observe",
        events: ["tool.before"],
        content: { default: "metadata" },
      },
    ]),
    options({
      fetch: async () => {
        requests++;
        throw new Error("Canceled observation must not start a request");
      },
      auth: auth({
        authenticate: () => {
          entered();
          return authentication;
        },
      }),
    }),
  );
  try {
    let settled = false;
    const work = hooks
      .dispatch("tool.before", tool(), {
        signal: controller.signal,
      })
      .then((result) => {
        settled = true;
        return result;
      });
    await waiting;
    assert.equal(settled, false);
    controller.abort();
    const result = await work;
    assert.deepEqual(result.response.result.effects, []);
    assert.deepEqual(await result.observations, [
      {
        backendId: "test.backend",
        subscriptionIndex: 0,
        phase: "observation",
        code: "INTERRUPTED",
        syntheticDenial: false,
      },
    ]);
    releaseAuthentication();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(requests, 0);
    assert.equal(result.interrupted, true);
  } finally {
    releaseAuthentication();
    await hooks.close();
  }
});
