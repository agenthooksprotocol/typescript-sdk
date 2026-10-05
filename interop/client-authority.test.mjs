import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks, ConfigurationError } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);
const input = {
  call: { id: "call" },
  path: "native",
  tool: { name: "read", origin: "native", input: { path: "README.md" } },
};
const subscription = (mode, events = ["tool.before"]) => ({
  mode,
  events,
  content: { default: "metadata" },
  ...(mode === "intercept"
    ? { timeoutMs: 1000, failurePolicy: "fail-closed" }
    : {}),
});
function registration(subscriptions) {
  return {
    protocolVersion: "draft",
    hooks: [
      {
        id: "test.authority",
        transport: { type: "http", url: "https://hooks.example/intercept" },
        subscriptions,
      },
    ],
  };
}
for (const [name, capabilities] of [
  ["empty shorthand", {}],
  ["omitted event", { "session.end": { modes: ["observe"] } }],
  ["intercept-only shorthand", { "tool.before": { effects: ["deny"] } }],
  [
    "explicit intercept-only declaration",
    {
      "tool.before": {
        modes: ["intercept"],
        capabilities: { effects: ["deny"] },
      },
    },
  ],
  [
    "empty modes",
    { "tool.before": { modes: [], capabilities: { effects: [] } } },
  ],
]) {
  test(`observation requires explicit authority: ${name}`, async () => {
    let deliveries = 0;
    const client = new Hooks(registration([subscription("observe")]), {
      source: "urn:test:authority",
      capabilities,
      fetch: async () => {
        deliveries++;
        return new Response(null, { status: 204 });
      },
    });
    try {
      await assert.rejects(client.toolBefore(input), ConfigurationError);
      assert.equal(deliveries, 0);
    } finally {
      await client.close();
    }
  });
}

test("explicit observe-only declaration delivers no interception or effect grants", async () => {
  const messages = [];
  const client = new Hooks(registration([subscription("observe")]), {
    source: "urn:test:authority",
    capabilities: { "tool.before": { modes: ["observe"] } },
    fetch: async (_url, init) => {
      messages.push(JSON.parse(init.body));
      return new Response(null, { status: 204 });
    },
  });
  try {
    const result = await client.toolBefore(input);
    assert.deepEqual(await result.observations, []);
    assert.deepEqual(result.response.result.effects, []);
    assert.equal(messages.length, 1);
    assert.equal(messages[0].method, "hooks/observe");
    assert.equal(Object.hasOwn(messages[0].params, "capabilities"), false);
  } finally {
    await client.close();
  }
});

for (const observe of [false, true]) {
  test(`short-circuit fallback observation is ${observe ? "explicitly granted" : "not inferred"}`, async () => {
    const messages = [];
    const capabilities = { effects: ["deny"] };
    const client = new Hooks(
      registration([subscription("intercept"), subscription("intercept")]),
      {
        source: "urn:test:authority",
        capabilities: {
          "tool.before": observe
            ? { modes: ["intercept", "observe"], capabilities }
            : capabilities,
        },
        fetch: async (_url, init) => {
          const message = JSON.parse(init.body);
          messages.push(message);
          return message.method === "hooks/observe"
            ? new Response(null, { status: 204 })
            : Response.json({
                jsonrpc: "2.0",
                id: message.id,
                result: {
                  protocolVersion: "draft",
                  effects: [{ type: "deny", reason: "Policy" }],
                },
              });
        },
      },
    );
    try {
      const result = await client.toolBefore(input);
      assert.deepEqual(await result.observations, []);
      assert.deepEqual(
        messages.map((message) => message.method),
        observe ? ["hooks/intercept", "hooks/observe"] : ["hooks/intercept"],
      );
    } finally {
      await client.close();
    }
  });
}

test("wildcard subscriptions intersect explicit modes without broadening them", async () => {
  let deliveries = 0;
  const client = new Hooks(registration([subscription("observe", ["*"])]), {
    source: "urn:test:authority",
    capabilities: { "tool.before": { effects: [] } },
    fetch: async () => {
      deliveries++;
      return new Response(null, { status: 204 });
    },
  });
  try {
    const result = await client.toolBefore(input);
    await result.observations;
    assert.equal(deliveries, 0);
  } finally {
    await client.close();
  }
});
