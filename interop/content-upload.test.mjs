import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  uploadBytes,
  createContentAdapter,
  rawUploadBytes,
  UploadStore,
  uploadURL,
  digest,
  authorizeUpload,
} from "./content-upload.mjs";
import { reply, listen, discovery } from "./common.mjs";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
test(
  "core runner isolates row and config content sources and reports actual uploads",
  { timeout: 15000 },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "ahp-core-sources-"));
    const store = new UploadStore(() => "scope");
    const receipts = [];
    const server = createServer(async (req, res) => {
      if (req.url === "/capabilities") return reply(res, 200, discovery);
      if (req.url === "/custom-upload") {
        const result = await store.receive(req);
        return reply(res, result.status, {
          ref: result.ref,
          size: result.size,
          sha256: result.sha256,
        });
      }
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const message = JSON.parse(raw);
      receipts.push(message);
      reply(res, 200, {
        jsonrpc: "2.0",
        id: message.id,
        result: { protocolVersion: "draft", effects: [] },
      });
    });
    const endpoint = await listen(server);
    const source = (ref, value) => {
      const bytes = Buffer.from(value);
      return {
        descriptor: { ref, size: bytes.length, sha256: digest(bytes) },
        bytes: bytes.toString("base64"),
      };
    };
    const first = source("config-source", "first"),
      second = source("row-source", "second");
    const row = (id, receipt, extra = {}) => ({
      id,
      ...extra,
      expected: {},
      request: {
        jsonrpc: "2.0",
        id,
        method: "hooks/intercept",
        params: {
          protocolVersion: "draft",
          capabilities: { effects: [] },
          event: {
            id,
            source: "urn:ahp:test",
            type: "tool.before",
            time: "2030-01-01T00:00:00Z",
            session: { id: "s" },
            call: { id },
            path: "native",
            tool: { name: "test", origin: "native", input: {} },
            items: [
              {
                id: "item",
                kind: "attachment",
                mediaType: "application/octet-stream",
                selection: "body",
                body: { ref: receipt.ref },
              },
            ],
          },
        },
      },
    });
    try {
      const scenarioFile = join(dir, "scenarios.json"),
        reportFile = join(dir, "report.json"),
        configFile = join(dir, "config.json");
      await writeFile(
        scenarioFile,
        JSON.stringify({
          version: 1,
          scenarios: [
            row("first", first.descriptor),
            row("second", second.descriptor, { contentSources: [second] }),
            row("missing", first.descriptor, { contentSources: [] }),
          ],
        }),
      );
      await writeFile(
        configFile,
        JSON.stringify({
          transport: "http",
          endpoint,
          scenarioFile,
          reportFile,
          contentSources: [first],
          subscriptions: [
            {
              content: { default: "body" },
              upload: {
                endpoint: endpoint + "/custom-upload",
                timeoutMs: 5000,
                maxBytes: 100,
              },
            },
          ],
        }),
      );
      const child = spawn(
        process.execPath,
        ["interop/client.mjs", "--config", configFile],
        { stdio: ["ignore", "ignore", "pipe"] },
      );
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      const exit = await new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", resolve);
      });
      assert.equal(exit, 1, stderr); // The empty row override must fail, not use cfg sources.
      const report = JSON.parse(await readFile(reportFile, "utf8"));
      assert.deepEqual(
        report.results.map((result) => result.status),
        ["passed", "passed", "failed"],
      );
      assert.equal(receipts.length, 2);
      for (const [index, source] of [first, second].entries()) {
        const descriptor = receipts[index].params.event.items[0].body;
        assert.notEqual(descriptor.ref, source.descriptor.ref);
        assert.deepEqual(report.results[index].contentUploads, [
          { sourceRef: source.descriptor.ref, descriptor: { ...source.descriptor, ref: descriptor.ref } },
        ]);
        assert.deepEqual(
          store.resolve("scope", descriptor),
          Buffer.from(source.bytes, "base64"),
        );
      }
      assert.deepEqual(report.results[2].contentUploads, []);
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      await rm(dir, { recursive: true, force: true });
    }
  },
);
test(
  "core stdio accepts only explicitly mismatched response-ID deadlines as negative evidence",
  { timeout: 20000 },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "ahp-core-response-id-"));
    const rows = ["wrong-response-id", "unrelated-timeout"].map((id) => ({
      id,
      expectError: true,
      ...(id === "unrelated-timeout" ? { barrier: "never-released" } : {}),
      request: {
        jsonrpc: "2.0",
        id,
        method: "hooks/intercept",
        params: {
          protocolVersion: "draft",
          capabilities: { effects: [] },
          event: {
            id,
            source: "urn:ahp:test",
            type: "tool.before",
            time: "2030-01-01T00:00:00Z",
            session: { id: "s" },
            call: { id },
            path: "native",
            tool: { name: "test", origin: "native", input: {} },
          },
        },
      },
      response: {
        jsonrpc: "2.0",
        id: id === "wrong-response-id" ? "different" : id,
        result: { protocolVersion: "draft", effects: [] },
      },
    }));
    try {
      const scenarioFile = join(dir, "scenarios.json"),
        serverConfig = join(dir, "server.json"),
        configFile = join(dir, "client.json"),
        reportFile = join(dir, "report.json");
      await writeFile(
        scenarioFile,
        JSON.stringify({ version: 1, scenarios: rows }),
      );
      await writeFile(
        serverConfig,
        JSON.stringify({
          transport: "stdio",
          scenarioFile,
          readinessFile: join(dir, "ready.json"),
          auth: { mode: "none" },
        }),
      );
      await writeFile(
        configFile,
        JSON.stringify({
          transport: "stdio",
          scenarioFile,
          serverConfig,
          reportFile,
          serverCommand: [process.execPath, "interop/server.mjs"],
          serverCwd: process.cwd(),
          subscriptions: [{ timeoutMs: 2500, failurePolicy: "fail-closed" }],
        }),
      );
      const child = spawn(
        process.execPath,
        ["interop/client.mjs", "--config", configFile],
        { stdio: ["ignore", "ignore", "pipe"] },
      );
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      const exit = await new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", resolve);
      });
      assert.equal(exit, 1, stderr);
      const { results } = JSON.parse(await readFile(reportFile, "utf8"));
      assert.deepEqual(
        results.map((result) => result.status),
        ["passed", "failed"],
      );
      assert.deepEqual(results[0].actual, { rejected: true });
      assert.equal(results[1].actual, null);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);
test("content sources require exact descriptors and integrity without repairing wire negatives", async () => {
  const bytes = Buffer.from([0, 255, 128]);
  const descriptor = {
    ref: "source",
    size: bytes.length,
    sha256: digest(bytes),
  };
  const sources = [{ descriptor, bytes: bytes.toString("base64") }];
  const adapter = createContentAdapter(sources);
  for (const body of [
    { ref: "missing" },
    { ...descriptor, size: 1 },
    { ...descriptor, sha256: "0".repeat(64) },
  ]) {
    const event = { items: [{ body }] };
    assert.throws(() => adapter.hydrate(event), /content source/);
    assert.equal(event.items[0].body, body);
  }
  assert.throws(
    () =>
      createContentAdapter([{ descriptor, bytes: "" }]).hydrate({
        items: [{ body: { ref: descriptor.ref } }],
      }),
    /integrity/,
  );
  const event = { items: [{ body: { ref: descriptor.ref } }] };
  adapter.hydrate(event);
  assert.deepEqual(
    Buffer.from(await new Response(event.items[0].body).arrayBuffer()),
    bytes,
  );
  assert.deepEqual(adapter.contentUploads, []);
});

test("content upload reports come from actual response clones and leave responses readable", async () => {
  const bytes = Buffer.from([0, 255, 128]);
  const descriptor = {
    ref: "source",
    size: bytes.length,
    sha256: digest(bytes),
  };
  const store = new UploadStore(() => "scope");
  let requests = 0;
  const server = createServer(async (req, res) => {
    requests++;
    const result = await store.receive(req);
    reply(res, result.status, {
      ref: result.ref,
      size: result.size,
      sha256: result.sha256,
    });
  });
  const endpoint = await listen(server);
  try {
    const adapter = createContentAdapter(
      [{ descriptor, bytes: bytes.toString("base64") }],
      fetch,
      [endpoint],
    );
    const event = { items: [{ body: { ref: descriptor.ref } }] };
    adapter.hydrate(event);
    const body = new Uint8Array(
      await new Response(event.items[0].body).arrayBuffer(),
    );
    const response = await adapter.fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        "content-length": String(body.length),
        "ahp-content-sha256": descriptor.sha256,
      },
      body,
    });
    const confirmed = await response.json();
    assert.equal(response.status, 201);
    assert.notEqual(confirmed.ref, descriptor.ref);
    assert.deepEqual(adapter.contentUploads, [
      { sourceRef: descriptor.ref, descriptor: confirmed },
    ]);
    assert.deepEqual(store.resolve("scope", confirmed), bytes);
    assert.equal(requests, 1);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("failed, mismatched and unrelated responses never fabricate content upload confirmations", async () => {
  const bytes = Buffer.from("abc");
  const descriptor = { ref: "source", size: 3, sha256: digest(bytes) };
  for (const [status, body, endpoint] of [
    [400, descriptor, "https://upload.test/"],
    [201, { ...descriptor, size: 99 }, "https://upload.test/"],
    [201, descriptor, "https://event.test/"],
    [201, {}, "https://upload.test/"],
  ]) {
    const adapter = createContentAdapter(
      [{ descriptor, bytes: bytes.toString("base64") }],
      async () =>
        new Response(JSON.stringify(body), {
          status,
          headers: { "content-type": "application/json" },
        }),
      ["https://upload.test/"],
    );
    adapter.hydrate({ items: [{ body: { ref: descriptor.ref } }] });
    const response = await adapter.fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/octet-stream" },
      body: bytes,
    });
    assert.deepEqual(await response.json(), body);
    assert.deepEqual(adapter.contentUploads, []);
  }
});
test("upload policies distinguish invalid credentials from denied authorization", () => {
  assert.equal(authorizeUpload({ uploadSubscriptions: {} }, undefined), 401);
  assert.equal(
    authorizeUpload({ uploadSubscriptions: {} }, "Bearer TEST-ONLY-unknown"),
    401,
  );
  assert.equal(
    authorizeUpload(
      {
        uploadSubscriptions: { denied: { anonymous: true, authorized: false } },
      },
      undefined,
    ),
    403,
  );
  assert.equal(
    authorizeUpload(
      { uploadSubscriptions: { allowed: { anonymous: true, scope: "body" } } },
      undefined,
    ),
    "body",
  );
});
test("SDK upload authenticates independently, preserves octets, allocates immutable scoped references", async () => {
  const store = new UploadStore(
    (a) =>
      a === "Bearer upload-secret"
        ? "sub"
        : a === "Bearer forbidden"
          ? 403
          : 401,
    10,
  );
  const captures = [];
  const server = createServer(async (req, res) => {
    captures.push(req.headers);
    if (req.url !== "/bytes?version=1") {
      req.resume();
      res.writeHead(404).end();
      return;
    }
    const result = await store.receive(req);
    reply(
      res,
      result.status,
      result.status === 201
        ? { ref: result.ref, size: result.size, sha256: result.sha256 }
        : {},
    );
  });
  const endpoint = await listen(server);
  try {
    const upload = {
      endpoint: endpoint + "/bytes?version=1",
      auth: { type: "bearer", tokenEnv: "UPLOAD", future: true },
      future: true,
    };
    const opts = {
        allowLoopback: true,
        env: { UPLOAD: "upload-secret", EVENT: "event-secret" },
      },
      bytes = new Uint8Array([0, 255, 128, 13, 10]);
    const result = await uploadBytes(upload, bytes, opts);
    assert.equal(result.status, 201);
    assert.deepEqual(store.resolve("sub", result.body), Buffer.from(bytes));
    const retry = await uploadBytes(upload, bytes, opts);
    assert.equal(retry.status, 201);
    assert.notEqual(retry.body.ref, result.body.ref);
    const changed = await uploadBytes(upload, new Uint8Array([1]), opts);
    assert.equal(changed.status, 201);
    assert.notEqual(changed.body.ref, result.body.ref);
    assert.deepEqual(store.resolve("sub", result.body), Buffer.from(bytes));
    assert.equal(
      (
        await rawUploadBytes(upload, bytes, {
          ...opts,
          env: { UPLOAD: "forbidden" },
        })
      ).status,
      403,
    );
    assert.equal(
      (await rawUploadBytes({ ...upload, auth: undefined }, bytes, opts))
        .status,
      401,
    );
    assert.equal(
      (
        await rawUploadBytes(upload, bytes, {
          ...opts,
          env: { UPLOAD: "event-secret" },
        })
      ).status,
      401,
    );
    assert.throws(() => store.resolve("other", result.body));
    assert.deepEqual(store.resolve("sub", { ref: result.body.ref }), Buffer.from(bytes));
    // Resolution trusts scoped storage, not untrusted event metadata.
    assert.deepEqual(store.resolve("sub", { ...result.body, sha256: "0".repeat(64) }), Buffer.from(bytes));
    assert.equal(
      (await uploadBytes(upload, new Uint8Array(), opts)).body.size,
      0,
    );
    assert.equal(
      (await rawUploadBytes(upload, new Uint8Array(11), opts)).status,
      413,
    );
    assert.equal(
      (
        await rawUploadBytes(upload, bytes, {
          ...opts,
          declaredHash: "0".repeat(64),
        })
      ).status,
      400,
    );
    assert.equal(
      (
        await rawUploadBytes(upload, bytes, {
          ...opts,
          declaredSize: bytes.length + 1,
        })
      ).status,
      400,
    );
    await assert.rejects(
      rawUploadBytes(upload, bytes, {
        ...opts,
        declaredHash: "bad\r\nInjected: true",
      }),
    );
    assert.ok(
      captures.every((headers) =>
        Object.keys(headers).every(
          (key) => !["ahp-subscription", "ahp-content-ref"].includes(key),
        ),
      ),
    );
    assert.throws(() => uploadURL(upload.endpoint));
    for (const invalid of [
      { maxBytes: "10" },
      { maxBytes: -1 },
      { timeoutMs: 0 },
      { auth: { type: "bearer", tokenEnv: "bad-name" } },
    ])
      await assert.rejects(uploadBytes({ ...upload, ...invalid }, bytes, opts));
    assert.equal(
      (await uploadBytes({ ...upload, maxBytes: 0 }, new Uint8Array(), opts))
        .status,
      201,
    );
    await assert.rejects(uploadBytes({ ...upload, maxBytes: 0 }, bytes, opts));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
test("only a validated synchronous descriptor confirms a body; redirects never follow", async () => {
  const bytes = Buffer.from("abc");
  const cases = [
    { status: 202 },
    { status: 204 },
    { status: 201, body: {} },
    { status: 201, body: { ref: "", size: 3, sha256: digest(bytes) } },
    { status: 201, body: { ref: "r", size: 4, sha256: digest(bytes) } },
    { status: 201, body: { ref: "r", size: 3, sha256: "0".repeat(64) } },
    {
      status: 201,
      body: { ref: "r", size: 3, sha256: digest(bytes) },
      media: "text/plain",
    },
    {
      status: 201,
      body: { ref: "r", size: 3, sha256: digest(bytes), future: true },
    },
  ];
  const server = createServer((req, res) => {
    req.resume();
    if (req.url === "/redirect") res.writeHead(307, { location: "/0" }).end();
    else {
      const row = cases[Number(req.url.slice(1))];
      res
        .writeHead(row.status, {
          "content-type": row.media ?? "application/json",
        })
        .end(JSON.stringify(row.body));
    }
  });
  const endpoint = await listen(server);
  try {
    for (let i = 0; i < cases.length; i++) {
      const task = uploadBytes({ endpoint: endpoint + "/" + i }, bytes, {
        allowLoopback: true,
      });
      if (i < 2) await assert.rejects(task);
      else if (i === cases.length - 1) assert.equal((await task).body.ref, "r");
      else await assert.rejects(task);
    }
    await assert.rejects(
      uploadBytes({ endpoint: endpoint + "/redirect" }, bytes, {
        allowLoopback: true,
      }),
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
