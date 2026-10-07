import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks } = await import(
  require.resolve("agenthooksprotocol/client")
);
const { hooks } = await import(
  require.resolve("agenthooksprotocol/server")
);
const caps = {
  effects: ["allow", "deny", "return", "modify"],
  modify: { input: { merge: true, replace: true } },
};
const tool = () => ({
  call: { id: "c" },
  path: "native",
  tool: { name: "read", origin: "native", input: { x: 1 } },
});
const seed = () => ({
  permission: "allow",
  candidate: { value: { cached: true }, provenance: { backend: "earlier" } },
  flow: "none",
  instructions: ["existing"],
  injections: [],
});
function setup(responses, failurePolicy = "fail-open") {
  return new Hooks(
    {
      protocolVersion: "draft",
      hooks: (responses.length ? responses : [[]]).map((_, i) => ({
        id: `policy.backend${i}`,
        transport: { type: "http", url: `https://policy.example/${i}` },
        subscriptions: [
          {
            mode: "intercept",
            events: [responses.length ? "tool.before" : "session.start"],
            timeoutMs: 1000,
            failurePolicy,
            content: { default: "metadata" },
          },
        ],
      })),
    },
    {
      source: "urn:test:final-state",
      capabilities: { "tool.before": caps, "session.start": { effects: [] } },
      fetch: async (url, init) => {
        const response = responses[Number(new URL(url).pathname.slice(1))];
        if (typeof response === "function") return response();
        return hooks.handle(new Request(url, init), () => ({
          effects: response,
        }));
      },
    },
  );
}
async function run(responses, options, failurePolicy) {
  const client = setup(responses, failurePolicy);
  try {
    return await client.dispatch("tool.before", tool(), options);
  } finally {
    await client.close();
  }
}

test("final state exposes accepted candidate and is detached from effects and initial state", async () => {
  const initialState = seed();
  const result = await run([[{ type: "return", value: { answer: [42] } }]], {
    initialState,
  });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.state, {
    ...seed(),
    candidate: { value: { answer: [42] } },
  });
  assert.deepEqual(initialState, seed());
  result.response.result.effects[0].value.answer.push(43);
  initialState.instructions.push("changed");
  assert.deepEqual(result.state.candidate.value.answer, [42]);
  assert.deepEqual(result.state.instructions, ["existing"]);
  assert.ok(Object.isFrozen(result.state));
  assert.ok(Object.isFrozen(result.state.candidate.value.answer));
  assert.throws(() => result.state.candidate.value.answer.push(44), TypeError);
  assert.throws(() => {
    result.state.permission = "deny";
  }, TypeError);
});

test("final state preserves initial candidate provenance without accepted replacement", async () => {
  const initialState = seed();
  const result = await run([[]], { initialState });
  assert.deepEqual(result.state, seed());
  assert.notEqual(result.state.candidate, initialState.candidate);
  assert.ok(!Object.isFrozen(initialState.candidate));
});

test("final state reflects candidate invalidation rather than replaying earlier returns", async () => {
  for (const responses of [
    [
      [
        {
          type: "modify",
          target: "input",
          operation: "merge",
          value: { x: 2 },
        },
      ],
    ],
    [
      [{ type: "return", value: 42 }, { type: "allow" }],
      [
        {
          type: "modify",
          target: "input",
          operation: "merge",
          value: { x: 2 },
        },
      ],
    ],
  ]) {
    const result = await run(responses, { initialState: seed() });
    assert.deepEqual(result.errors, []);
    assert.equal(result.state.candidate, null);
    assert.equal(result.state.permission, "none");
    assert.equal(result.event.tool.input.x, 2);
  }
});

test("final state includes denial settlement and fail-closed synthetic denial", async () => {
  for (const responses of [
    [[{ type: "deny", reason: "policy" }]],
    [
      () => {
        throw new Error("unavailable");
      },
    ],
  ]) {
    const result = await run(
      responses,
      { initialState: seed() },
      "fail-closed",
    );
    assert.equal(result.state.permission, "deny");
    assert.equal(result.state.candidate, null);
    assert.deepEqual(result.state.instructions, ["existing"]);
  }
});

test("rejected responses and fail-open errors preserve the actual prior state", async () => {
  for (const responses of [
    [
      [
        {
          type: "modify",
          target: "input",
          operation: "merge",
          value: { x: 2 },
        },
        { type: "flow", operation: "continue" },
      ],
    ],
    [
      () => {
        throw new Error("unavailable");
      },
    ],
  ]) {
    const result = await run(responses, { initialState: seed() });
    assert.equal(result.errors.length, 1);
    assert.deepEqual(result.state, seed());
    assert.equal(result.event.tool.input.x, 1);
  }
});

test("no handlers and early interruption return detached initial or neutral state", async () => {
  for (const interrupted of [false, true]) {
    for (const initialState of [
      undefined,
      seed(),
      { ...seed(), permission: "deny" },
    ]) {
      const controller = new AbortController();
      if (interrupted) controller.abort();
      const result = await run([], { initialState, signal: controller.signal });
      assert.equal(result.interrupted, interrupted);
      assert.deepEqual(
        result.state,
        initialState ?? { candidate: null, permission: "none" },
      );
      assert.notEqual(result.state, initialState);
      assert.ok(Object.isFrozen(result.state));
    }
  }
});

test("interruption retains last accepted state but does not grant execution", async () => {
  const controller = new AbortController();
  const result = await run(
    [
      [{ type: "return", value: 42 }, { type: "allow" }],
      () =>
        new Promise((resolve) =>
          setTimeout(() => {
            controller.abort();
            resolve(new Response(null, { status: 204 }));
          }, 0),
        ),
    ],
    { signal: controller.signal },
  );
  assert.equal(result.interrupted, true);
  assert.equal(result.state.candidate.value, 42);
  assert.equal(result.state.permission, "allow");
  assert.ok(
    !result.response.result.effects.some(
      (e) => e.type === "return" || e.type === "allow",
    ),
  );
});

test("final-state projection does not append continuation instructions twice", async () => {
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "policy.finish",
          transport: { type: "http", url: "https://policy.example/finish" },
          subscriptions: [
            {
              mode: "intercept",
              events: ["turn.finish.before"],
              timeoutMs: 1000,
              failurePolicy: "fail-open",
              content: { default: "metadata" },
            },
          ],
        },
      ],
    },
    {
      source: "urn:test:final-state",
      capabilities: {
        "turn.finish.before": {
          effects: ["flow"],
          flow: {
            operations: ["continue"],
            continuationCount: 0,
            maxContinuations: 2,
            remainingContinuations: 2,
          },
        },
      },
      fetch: async (url, init) =>
        hooks.handle(new Request(url, init), () => ({
          effects: [
            { type: "flow", operation: "continue", instruction: "Check once" },
          ],
        })),
    },
  );
  try {
    const result = await client.dispatch(
      "turn.finish.before",
      {
        turn: { id: "t" },
        outcome: "completed",
        continuationCount: 0,
        items: [],
      },
      {
        initialState: {
          candidate: null,
          permission: "none",
          instructions: ["Earlier"],
        },
      },
    );
    assert.deepEqual(result.errors, []);
    assert.equal(result.state.flow, "continue");
    assert.deepEqual(result.state.instructions, ["Earlier", "Check once"]);
    assert.ok(Object.isFrozen(result.state.instructions));
  } finally {
    await client.close();
  }
});
