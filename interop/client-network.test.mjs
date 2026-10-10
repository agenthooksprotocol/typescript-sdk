import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks, auth } = await import(
  require.resolve("agenthooksprotocol/client")
);
const { hooks, attachments } = await import(
  require.resolve("agenthooksprotocol/server")
);

// The injected adapter changes network mechanics only. The real client and
// server APIs retain wire construction, validation, and upload preparation.
test("client network delegation preserves independent event and upload authentication", async () => {
  const received = [];
  const bindings = [];
  const provider = auth({
    resolveEnvironmentVariable: (name, context) => {
      bindings.push({ name, purpose: context.purpose });
      return { EVENT_TOKEN: "event-token", UPLOAD_TOKEN: "upload-token" }[name];
    },
  });
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "network.fixture",
          transport: { type: "http", url: "https://event.example.test/hooks" },
          authentication: { type: "bearer", tokenEnv: "EVENT_TOKEN" },
          subscriptions: [
            {
              mode: "intercept",
              events: ["tool.before"],
              timeoutMs: 3000,
              failurePolicy: "fail-closed",
              content: { default: "body" },
              upload: {
                endpoint: "https://upload.example.test/attachments",
                maxBytes: 1024,
                timeoutMs: 3000,
                auth: { type: "bearer", tokenEnv: "UPLOAD_TOKEN" },
              },
            },
          ],
        },
      ],
    },
    {
      source: "urn:network:fixture",
      capabilities: { "tool.before": { effects: [] } },
      auth: provider,
      fetch: async (url, init) => {
        assert.equal(init.redirect, "error");
        assert.ok(init.signal instanceof AbortSignal);
        const request = new Request(url, init);
        received.push({
          url: String(url),
          authorization: request.headers.get("authorization"),
        });
        if (url === "https://upload.example.test/attachments") {
          const upload = attachments.parse(request);
          const bytes = await new Response(upload.body).arrayBuffer();
          assert.equal(new TextDecoder().decode(bytes), "network payload");
          return attachments.response({
            ref: "stored-body",
            size: upload.size,
            sha256: upload.sha256,
          });
        }
        assert.equal(url, "https://event.example.test/hooks");
        return hooks.handle(request, (message) => {
          assert.equal(message.method, "hooks/intercept");
          assert.equal(message.params.event.items[0].body.ref, "stored-body");
          assert.equal(message.id, message.params.event.id);
          return { effects: [] };
        });
      },
    },
  );
  try {
    const result = await client.dispatch("tool.before", {
      id: "network-occurrence",
      path: "native",
      call: { id: "network-call" },
      tool: { name: "network", origin: "native", input: {} },
      items: [
        {
          id: "payload",
          kind: "attachment",
          mediaType: "application/octet-stream",
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("network payload"));
              controller.close();
            },
          }),
        },
      ],
    });
    assert.deepEqual(result.errors, []);
    assert.deepEqual(await result.observations, []);
    assert.deepEqual(bindings, [
      { name: "UPLOAD_TOKEN", purpose: "upload" },
      { name: "EVENT_TOKEN", purpose: "event" },
    ]);
    assert.deepEqual(received, [
      {
        url: "https://upload.example.test/attachments",
        authorization: "Bearer upload-token",
      },
      {
        url: "https://event.example.test/hooks",
        authorization: "Bearer event-token",
      },
    ]);
  } finally {
    await client.close();
  }
});
