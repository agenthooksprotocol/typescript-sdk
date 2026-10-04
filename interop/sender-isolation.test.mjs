import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { Readable } from "node:stream";
import { listen } from "./common.mjs";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks, auth } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);
const { hooks, attachments } = await import(
  require.resolve("@agenthooksprotocol/sdk/server")
);

test("public sender never inherits event Authorization when upload auth is omitted", async () => {
  const captures = [],
    events = [],
    stored = new Map();
  const request = (incoming) =>
    new Request(`http://127.0.0.1${incoming.url}`, {
      method: incoming.method,
      headers: incoming.headers,
      body: Readable.toWeb(incoming),
      duplex: "half",
    });
  const respond = async (outgoing, response) => {
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(new Uint8Array(await response.arrayBuffer()));
  };
  const uploadServer = createServer(async (incoming, outgoing) => {
    try {
      captures.push({
        authorization: incoming.headers.authorization,
        rawHeaders: [...incoming.rawHeaders],
      });
      assert.equal(incoming.headers.authorization, undefined);
      const upload = attachments.parse(request(incoming));
      const bytes = Buffer.from(await new Response(upload.body).arrayBuffer());
      const ref = `stored-${stored.size}`;
      stored.set(ref, bytes);
      await respond(
        outgoing,
        attachments.response({ ref, size: upload.size, sha256: upload.sha256 }),
      );
    } catch {
      outgoing.writeHead(500).end();
    }
  });
  const eventServer = createServer(async (incoming, outgoing) => {
    if (
      incoming.headers.authorization !== "Bearer TEST-ONLY-event-credential"
    ) {
      outgoing.writeHead(401).end();
      return;
    }
    await respond(
      outgoing,
      await hooks.handle(request(incoming), (message) => {
        events.push({ authorization: incoming.headers.authorization, message });
        assert.ok(stored.has(message.params.event.items[0].body.ref));
        return { effects: [] };
      }),
    );
  });
  let client;
  try {
    const uploadEndpoint = await listen(uploadServer),
      endpoint = await listen(eventServer);
    const bytes = Buffer.from([0, 255, 128, 13, 10]);
    client = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "test.isolation",
            transport: { type: "http", url: endpoint },
            authentication: { type: "bearer", tokenRef: "event" },
            subscriptions: [
              {
                mode: "intercept",
                events: ["tool.before"],
                timeoutMs: 5000,
                failurePolicy: "fail-closed",
                content: { default: "body" },
                upload: {
                  endpoint: uploadEndpoint,
                  timeoutMs: 5000,
                  maxBytes: 1024,
                },
              },
            ],
          },
        ],
      },
      {
        source: "urn:typescript:isolation",
        capabilities: { "tool.before": { effects: [] } },
        auth: auth({
          resolveCredentialReference(reference) {
            assert.equal(reference, "event");
            return "TEST-ONLY-event-credential";
          },
        }),
      },
    );
    const result = await client.toolBefore({
      id: "unrelated-correlation",
      time: "2026-01-01T00:00:00Z",
      call: { id: "call" },
      path: "native",
      tool: { name: "task", origin: "native", input: { task: 1 } },
      items: [
        {
          id: "body-item",
          kind: "text",
          role: "user",
          mediaType: "application/octet-stream",
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(bytes);
              controller.close();
            },
          }),
        },
      ],
    });
    assert.deepEqual(result.errors, []);
    assert.deepEqual(await result.observations, []);
    assert.deepEqual(result.response.result.effects, []);
    assert.equal(captures.length, 1);
    assert.equal(captures[0].authorization, undefined);
    assert.equal(
      captures[0].rawHeaders.some(
        (value, index) =>
          index % 2 === 0 && value.toLowerCase() === "authorization",
      ),
      false,
    );
    assert.deepEqual([...stored.values()], [bytes]);
    assert.equal(events.length, 1);
    assert.equal(events[0].authorization, "Bearer TEST-ONLY-event-credential");
    const message = events[0].message;
    assert.equal(message.id, "unrelated-correlation");
    assert.equal(message.params.event.id, message.id);
    assert.equal(message.params.event.source, "urn:typescript:isolation");
    assert.deepEqual({ ...message.params.event.tool.input }, { task: 1 });
    assert.equal(message.params.event.items[0].body.ref, "stored-0");
  } finally {
    await client?.close();
    await Promise.all(
      [eventServer, uploadServer].map((server) => {
        server.closeAllConnections();
        return new Promise((resolve) => server.close(resolve));
      }),
    );
  }
});

test("elicitation preserves explicit unauthorized upload headers without a bypass flag", async () => {
  const { spawn } = await import("node:child_process");
  const seen = [];
  const server = createServer(async (req, res) => {
    for await (const _chunk of req) {
      /* drain explicit negative payload */
    }
    seen.push(req.headers.authorization);
    res.writeHead(401).end();
  });
  const endpoint = await listen(server);
  try {
    for (const header of ["Authorization", "authorization"]) {
      const child = spawn(
        process.execPath,
        ["interop/elicitation.mjs", "client"],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      let stdout = "",
        stderr = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      const exited = new Promise((resolve, reject) => {
        child.on("error", reject);
        child.on("exit", resolve);
      });
      child.stdin.end(
        JSON.stringify({
          endpoint,
          token: "event-secret",
          uploadToken: "upload-secret",
          steps: [
            {
              path: "/upload",
              bytes: Buffer.from("x").toString("base64"),
              headers: {
                [header]: "Bearer unauthorized-upload",
                "Content-Type": "application/octet-stream",
              },
            },
          ],
        }),
      );
      assert.equal(await exited, 0, stderr);
      assert.deepEqual(JSON.parse(stdout), [{ status: 401, body: "" }]);
    }
    assert.deepEqual(seen, [
      "Bearer unauthorized-upload",
      "Bearer unauthorized-upload",
    ]);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
