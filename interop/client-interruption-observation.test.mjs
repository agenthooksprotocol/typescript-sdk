import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);
const { hooks } = await import(
  require.resolve("@agenthooksprotocol/sdk/server")
);
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
function scenario() {
  const pending = deferred();
  const releasePending = deferred();
  const observed = deferred();
  const releaseObservers = deferred();
  const messages = [];
  let intercepts = 0;
  let observations = 0;
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "test.policy",
          transport: { type: "http", url: "https://policy.example/hooks" },
          subscriptions: ["intercept", "intercept", "intercept", "observe"].map(
            (mode) => ({
              mode,
              events: ["tool.before"],
              content: { default: "metadata" },
              ...(mode === "intercept"
                ? { timeoutMs: 3000, failurePolicy: "fail-closed" }
                : {}),
            }),
          ),
        },
      ],
    },
    {
      source: "urn:test:interruption",
      observationTimeoutMs: 3000,
      capabilities: {
        "tool.before": {
          effects: ["deny", "modify", "message", "allow", "return"],
          modify: { input: { merge: true, replace: false } },
        },
      },
      fetch: (url, init) =>
        hooks.handle(new Request(url, init), async (message) => {
          messages.push(structuredClone(message));
          if (message.method === "hooks/observe") {
            observations++;
            if (observations === 2) observed.resolve();
            await releaseObservers.promise;
            return;
          }
          intercepts++;
          if (intercepts === 1)
            return {
              effects: [
                {
                  type: "modify",
                  target: "input",
                  operation: "merge",
                  value: { x: 2 },
                },
                { type: "allow" },
                { type: "return", value: "cached" },
              ],
            };
          pending.resolve();
          await releasePending.promise;
          return {
            effects: [
              {
                type: "modify",
                target: "input",
                operation: "merge",
                value: { x: 999 },
              },
              { type: "message", text: "discarded pending response" },
            ],
          };
        }),
    },
  );
  return {
    client,
    messages,
    pending,
    releasePending,
    observed,
    releaseObservers,
  };
}
const tool = () => ({
  id: "interrupted-boundary",
  call: { id: "c" },
  path: "native",
  tool: { name: "read", origin: "native", input: { x: 1 } },
});

test(
  "interruption observes uncalled and explicit subscriptions with accepted content without delaying settlement",
  { timeout: 10000 },
  async () => {
    const s = scenario();
    const controller = new AbortController();
    try {
      await s.client.initialized;
      const work = s.client.toolBefore(tool(), { signal: controller.signal });
      await s.pending.promise;
      controller.abort();
      const result = await work; // Observers deliberately remain blocked.
      assert.equal(result.interrupted, true);
      assert.equal(result.event.tool.input.x, 2);
      assert.deepEqual(
        result.response.result.effects.map((e) => e.type),
        ["modify"],
      );
      assert.equal(result.errors.length, 1);
      assert.equal(result.errors[0].syntheticDenial, false);
      await s.observed.promise;
      const notifications = s.messages.filter(
        (m) => m.method === "hooks/observe",
      );
      assert.equal(notifications.length, 2); // One uncalled interceptor + explicit observer; no duplicates.
      for (const m of notifications) {
        assert.equal(m.params.event.id, "interrupted-boundary");
        assert.equal(m.params.event.source, "urn:test:interruption");
        assert.equal(m.params.event.tool.input.x, 2);
      }
      s.releaseObservers.resolve();
      assert.deepEqual(await result.observations, []);
    } finally {
      s.releasePending.resolve();
      s.releaseObservers.resolve();
      await s.client.close();
    }
  },
);

test(
  "closing an interrupted chain starts no observer callbacks",
  { timeout: 10000 },
  async () => {
    const s = scenario();
    try {
      await s.client.initialized;
      const work = s.client.toolBefore(tool());
      await s.pending.promise;
      await s.client.close();
      const result = await work;
      assert.equal(result.interrupted, true);
      assert.deepEqual(await result.observations, []);
      assert.equal(
        s.messages.filter((m) => m.method === "hooks/observe").length,
        0,
      );
    } finally {
      s.releasePending.resolve();
      s.releaseObservers.resolve();
      await s.client.close();
    }
  },
);
