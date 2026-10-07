import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createServer } from "node:http";
import { Readable } from "node:stream";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { hooks, attachments } = await import(
  require.resolve("agenthooksprotocol/server")
);
const { Hooks } = await import(
  require.resolve("agenthooksprotocol/client")
);

test(
  "public Hooks HTTP client reaches server helpers and userland storage before policy evaluation",
  { timeout: 15000 },
  async () => {
    const bytes = new Uint8Array([0, 255, 128, 65]);
    const stored = new Map();
    const calls = [];
    // Application storage, not an SDK reference resolver. Commit only after EOF.
    const storage = {
      async save(body) {
        const value = new Uint8Array(await new Response(body).arrayBuffer());
        const ref = `opaque-${stored.size}`;
        stored.set(ref, value);
        return ref;
      },
    };
    let observed;
    const observedPromise = new Promise((resolve) => {
      observed = resolve;
    });
    const policyService = {
      handle(message, user) {
        assert.equal(user.id, "explicitly-authorized-local-test");
        calls.push(message.method);
        if (message.method === "hooks/observe") {
          observed();
          return;
        }
        assert.equal(message.method, "hooks/intercept");
        const descriptor = message.params.event.items[0].body;
        assert.deepEqual(stored.get(descriptor.ref), bytes);
        return {
          effects: [
            {
              type: "modify",
              target: "input",
              operation: "merge",
              value: { checked: true },
            },
          ],
        };
      },
    };
    const server = createServer(async (incoming, outgoing) => {
      try {
        const request = new Request(`http://127.0.0.1${incoming.url}`, {
          method: incoming.method,
          headers: incoming.headers,
          body: Readable.toWeb(incoming),
          duplex: "half",
        });
        let response;
        if (incoming.url === "/upload?receiver=one") {
          calls.push("upload");
          const upload = attachments.parse(request);
          const ref = await storage.save(upload.body);
          response = attachments.response({
            ref,
            size: upload.size,
            sha256: upload.sha256,
          });
        } else {
          // This controlled test explicitly permits anonymous calls. Production
          // authentication and authorization belong here, before the SDK helper.
          const user = { id: "explicitly-authorized-local-test" };
          response = await hooks.handle(request, (message) =>
            policyService.handle(message, user),
          );
        }
        outgoing.writeHead(
          response.status,
          Object.fromEntries(response.headers),
        );
        outgoing.end(new Uint8Array(await response.arrayBuffer()));
      } catch {
        outgoing.writeHead(500).end();
      }
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const client = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "test.server",
            transport: { type: "http", url: `${origin}/hooks` },
            subscriptions: [
              {
                mode: "intercept",
                events: ["tool.before"],
                timeoutMs: 3000,
                failurePolicy: "fail-closed",
                content: { default: "body" },
                upload: {
                  endpoint: `${origin}/upload?receiver=one`,
                  timeoutMs: 3000,
                  maxBytes: 100,
                },
              },
              {
                mode: "observe",
                events: ["tool.before"],
                content: { default: "metadata" },
              },
            ],
          },
        ],
      },
      {
        source: "urn:test:harness",
        capabilities: {
          "tool.before": {
            modes: ["intercept", "observe"],
            capabilities: {
              effects: ["modify"],
              modify: { input: { merge: true, replace: true } },
            },
          },
        },
      },
    );
    try {
      const result = await client.dispatch("tool.before", {
        call: { id: "c" },
        path: "native",
        tool: { name: "read", origin: "native", input: { path: "a" } },
        items: [
          {
            id: "item",
            kind: "text",
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
      assert.deepEqual(result.event.tool.input, { path: "a", checked: true });
      await observedPromise;
      assert.deepEqual(calls, ["upload", "hooks/intercept", "hooks/observe"]);
      assert.equal(stored.size, 1);
    } finally {
      await client.close();
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  },
);
