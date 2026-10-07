import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { Hooks, ConfigurationError, composeResponse } = await import(
  require.resolve("agenthooksprotocol/client")
);
const { hooks } = await import(
  require.resolve("agenthooksprotocol/server")
);
const caps = {
  effects: ["allow", "ask", "deny", "return", "modify", "flow"],
  modify: { input: { merge: true, replace: true } },
  flow: { operations: ["stop"] },
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
  instructions: [],
  injections: [],
});
function setup(
  responses,
  staticCaps = caps,
  extra = {},
  failurePolicy = "fail-open",
) {
  const seen = [];
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: responses.map((_, i) => ({
        id: `policy.backend${i}`,
        transport: { type: "http", url: `https://policy.example/${i}` },
        subscriptions: [
          {
            mode: "intercept",
            events: ["tool.before"],
            timeoutMs: 1000,
            failurePolicy,
            content: { default: "metadata" },
          },
        ],
      })),
    },
    {
      ...extra,
      source: "urn:test:state",
      capabilities: {
        "tool.before": {
          modes: ["intercept", "observe"],
          capabilities: staticCaps,
        },
      },
      fetch: async (url, init) =>
        hooks.handle(new Request(url, init), (message) => {
          seen.push(structuredClone(message));
          if (message.method === "hooks/observe") return;
          return { effects: responses[Number(new URL(url).pathname.slice(1))] };
        }),
    },
  );
  return { client, seen };
}
test("event-map delivery modes never infer elicitation answer grants", async () => {
  const capabilities = {
    "user.elicitation.request": { effects: ["deny"] },
    "session.start": { modes: ["observe"] },
    "session.end": { modes: ["observe"] },
  };
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "test.observer",
          transport: { type: "http", url: "https://hooks.example/observe" },
          subscriptions: [
            {
              mode: "observe",
              events: ["session.end"],
              content: { default: "metadata" },
            },
          ],
        },
      ],
    },
    {
      source: "urn:test:mode-authority",
      capabilities,
    },
  );
  try {
    const start = await client.dispatch("session.start", {
      session: { id: "session" },
      harness: { name: "test", version: "1" },
      permissionMode: "default",
      trigger: "startup",
      items: [],
    });
    const event = start.event.manifest.events.find(
      (event) => event.event === "user.elicitation.request",
    );
    assert.deepEqual(event.modes, ["intercept"]);
    assert.deepEqual(event.capabilities, { effects: ["deny"] });
    assert.equal(Object.hasOwn(event.capabilities, "elicitation"), false);
    await assert.rejects(
      client.dispatch(
        "user.elicitation.request",
        {
          elicitation: { mode: "form", server: "test" },
        },
        { capabilities: { effects: ["deny"], elicitation: { form: {} } } },
      ),
      ConfigurationError,
    );
    assert.deepEqual(capabilities, {
      "user.elicitation.request": { effects: ["deny"] },
      "session.start": { modes: ["observe"] },
      "session.end": { modes: ["observe"] },
    });
  } finally {
    await client.close();
  }
});

test("public Hooks sends exact initial state and complete narrowed capabilities", async () => {
  const { client, seen } = setup([[], []]);
  const state = seed();
  const narrowed = { effects: ["deny"] };
  try {
    const result = await client.dispatch("tool.before", tool(), {
      initialState: state,
      capabilities: narrowed,
    });
    assert.deepEqual(result.errors, []);
    assert.deepEqual(
      seen.map((m) => m.params.state),
      [state, state],
    );
    assert.deepEqual(
      seen.map((m) => m.params.capabilities),
      [narrowed, narrowed],
    );
    assert.deepEqual(state, seed());
  } finally {
    await client.close();
  }
});
test("changed input invalidates preseeded candidate/provenance and allow atomically", async () => {
  const { client, seen } = setup([
    [{ type: "modify", target: "input", operation: "merge", value: { x: 2 } }],
    [],
  ]);
  try {
    const result = await client.dispatch("tool.before", tool(), {
      initialState: seed(),
    });
    assert.deepEqual(result.errors, []);
    assert.equal(seen[1].params.state.candidate, null);
    assert.equal(seen[1].params.state.permission, "none");
    assert.equal(seen[1].params.event.tool.input.x, 2);
  } finally {
    await client.close();
  }
});
test("rejected compound preserves preseeded state and effective input", async () => {
  const { client, seen } = setup([
    [
      { type: "modify", target: "input", operation: "merge", value: { x: 2 } },
      { type: "flow", operation: "continue" },
    ],
    [],
  ]);
  try {
    const result = await client.dispatch("tool.before", tool(), {
      initialState: seed(),
    });
    assert.equal(result.errors.length, 1);
    assert.deepEqual(seen[1].params.state, seed());
    assert.equal(seen[1].params.event.tool.input.x, 1);
  } finally {
    await client.close();
  }
});
test("later return replaces provenance; ask survives later allow", async () => {
  const { client, seen } = setup([
    [{ type: "return", value: 5 }, { type: "allow" }],
    [],
  ]);
  try {
    const result = await client.dispatch("tool.before", tool(), {
      initialState: { ...seed(), permission: "ask" },
    });
    assert.deepEqual(result.errors, []);
    assert.deepEqual(seen[1].params.state.candidate, { value: 5 });
    assert.equal(seen[1].params.state.permission, "ask");
    assert.ok(!result.response.result.effects.some((e) => e.type === "allow"));
  } finally {
    await client.close();
  }
});
test("invalid state and widening fail before delivery", async () => {
  const { client, seen } = setup([[]]);
  try {
    await assert.rejects(
      client.dispatch("tool.before", tool(), {
        initialState: { permission: "allow" },
      }),
      ConfigurationError,
    );
    await assert.rejects(
      client.dispatch("tool.before", tool(), {
        capabilities: { effects: ["inject"] },
      }),
      ConfigurationError,
    );
    await assert.rejects(
      client.dispatch("tool.before", tool(), {
        capabilities: {
          effects: ["modify"],
          modify: { output: { replace: true } },
        },
      }),
      ConfigurationError,
    );
    assert.equal(seen.length, 0);
  } finally {
    await client.close();
  }
});
test("preseeded terminal state reaches the first receiver and settles after acceptance", async () => {
  for (const state of [
    { ...seed(), permission: "deny" },
    { ...seed(), flow: "stop" },
  ]) {
    for (const response of [
      [],
      [{ type: "allow" }],
      [{ type: "return", value: 42 }],
      [{ type: "allow" }, { type: "return", value: 42 }],
    ]) {
      const { client, seen } = setup([response, []]);
      try {
        const result = await client.dispatch("tool.before", tool(), {
          initialState: state,
        });
        await result.observations;
        assert.deepEqual(result.errors, []);
        assert.deepEqual(
          seen.map((m) => m.method),
          ["hooks/intercept", "hooks/observe"],
        );
        assert.deepEqual(seen[0].params.state, state);
        assert.ok(
          !result.response.result.effects.some((e) => e.type === "return"),
        );
        if (state.permission === "deny")
          assert.ok(
            !result.response.result.effects.some((e) => e.type === "allow"),
          );
      } finally {
        await client.close();
      }
    }
  }
});
test("complete narrowing validates controls and continuation budgets without merging omissions", async () => {
  const advertised = {
    ...caps,
    flow: {
      operations: ["stop"],
      maxContinuations: 2,
      remainingContinuations: 1,
      continuationCount: 1,
    },
  };
  const { client, seen } = setup([[]], advertised);
  try {
    const narrowed = {
      effects: ["flow"],
      flow: { operations: ["stop"], futureHint: { opaque: true } },
    };
    const result = await client.dispatch("tool.before", tool(), {
      capabilities: narrowed,
    });
    assert.deepEqual(result.errors, []);
    assert.deepEqual(seen[0].params.capabilities, narrowed);
    for (const flow of [
      { operations: ["stop", "continue"] },
      { operations: ["stop"], maxContinuations: 3 },
      { operations: ["stop"], remainingContinuations: 2 },
      { operations: ["stop"], continuationCount: 0 },
    ])
      await assert.rejects(
        client.dispatch("tool.before", tool(), {
          capabilities: { effects: ["flow"], flow },
        }),
        ConfigurationError,
      );
    assert.equal(seen.length, 1);
  } finally {
    await client.close();
  }
});

test("stop dominates continuation without dropping ordered instructions", () => {
  const event = {
    id: "finish",
    type: "turn.finish.before",
    source: "urn:test:state",
    time: "2026-01-01T00:00:00Z",
    continuationCount: 0,
    items: [],
  };
  const capabilities = {
    effects: ["flow"],
    flow: {
      operations: ["stop", "continue"],
      continuationCount: 0,
      maxContinuations: 1,
      remainingContinuations: 1,
    },
  };
  const stop = { type: "flow", operation: "stop", reason: "settled" };
  const continuation = {
    type: "flow",
    operation: "continue",
    instruction: "Check the result",
  };
  for (const effects of [
    [stop, continuation],
    [continuation, stop],
  ]) {
    const result = composeResponse(
      event,
      [],
      {
        jsonrpc: "2.0",
        id: "finish",
        result: { protocolVersion: "draft", effects },
      },
      capabilities,
    );
    assert.equal(result.shortCircuit, true);
    assert.equal(result.state.flow, "stop");
    assert.deepEqual(result.state.instructions, ["Check the result"]);
    assert.deepEqual(result.effects, effects);
  }
});

test("host input validation follows SDK acceptance, without atomic protocol rejection", async () => {
  for (const failurePolicy of ["fail-open", "fail-closed"]) {
    const effects = [
      { type: "message", text: "protocol accepted" },
      {
        type: "modify",
        target: "input",
        operation: "replace",
        value: { task: 0 },
      },
    ];
    const { client, seen } = setup(
      [effects, []],
      { ...caps, effects: [...caps.effects, "message"] },
      {},
      failurePolicy,
    );
    try {
      const input = tool();
      input.tool.input = { task: 1 };
      const result = await client.dispatch("tool.before", input);
      assert.deepEqual(result.errors, []);
      assert.equal(result.event.tool.input.task, 0);
      assert.equal(seen[1].params.event.tool.input.task, 0);
      assert.deepEqual(result.response.result.effects, effects);
      // Host refuses execution; it does not roll back SDK effects or invoke
      // subscription failure policy. task > 0 is not an AHP constraint.
      const hostAccepted =
        Number.isInteger(result.event.tool.input.task) &&
        result.event.tool.input.task > 0;
      let executions = 0;
      if (hostAccepted) executions++;
      assert.equal(hostAccepted, false);
      assert.equal(executions, 0);
    } finally {
      await client.close();
    }
  }
});
test("initial host input rejection happens in userland before calling Hooks", async () => {
  const { client, seen } = setup([[]]);
  try {
    const input = tool();
    input.tool.input = { task: 0 };
    const hostAccepted =
      Number.isInteger(input.tool.input.task) && input.tool.input.task > 0;
    if (hostAccepted) await client.dispatch("tool.before", input);
    assert.equal(hostAccepted, false);
    assert.equal(seen.length, 0);
  } finally {
    await client.close();
  }
});
test("pending state omits unrelated neutral fields but preserves explicit fields", async () => {
  for (const state of [
    { permission: "none", candidate: null },
    {
      permission: "none",
      candidate: null,
      flow: "none",
      instructions: [],
      injections: [],
    },
  ]) {
    const { client, seen } = setup([[], []]);
    try {
      const result = await client.dispatch("tool.before", tool(), {
        initialState: state,
      });
      assert.deepEqual(result.errors, []);
      assert.deepEqual(seen[1].params.state, state);
    } finally {
      await client.close();
    }
  }
});
test("immediate abort returns an interrupted result without auth, delivery or content reads", async () => {
  let authCalls = 0;
  let pulls = 0;
  const { client, seen } = setup([[]], caps, {
    auth: {
      authenticate() {
        authCalls++;
        throw new Error("must not authenticate");
      },
    },
  });
  const controller = new AbortController();
  controller.abort();
  try {
    const input = tool();
    input.items = [
      {
        id: "body",
        kind: "text",
        mediaType: "text/plain",
        body: new ReadableStream(
          {
            pull() {
              pulls++;
            },
          },
          { highWaterMark: 0 },
        ),
      },
    ];
    const result = await client.dispatch("tool.before", input, {
      signal: controller.signal,
    });
    assert.equal(result.interrupted, true);
    assert.deepEqual(result.response.result.effects, []);
    assert.deepEqual(await result.observations, []);
    assert.equal(authCalls, 0);
    assert.equal(pulls, 0);
    assert.equal(seen.length, 0);
  } finally {
    await client.close();
  }
});

test("host validation can inspect effective input without reading content streams", async () => {
  let pulls = 0;
  const { client, seen } = setup(
    [
      [
        {
          type: "modify",
          target: "input",
          operation: "merge",
          value: { x: 2 },
        },
      ],
      [],
    ],
    caps,
  );
  try {
    const input = tool();
    input.items = [
      {
        id: "body",
        kind: "text",
        mediaType: "text/plain",
        body: new ReadableStream(
          {
            pull() {
              pulls++;
            },
          },
          { highWaterMark: 0 },
        ),
      },
    ];
    const result = await client.dispatch("tool.before", input);
    assert.deepEqual(result.errors, []);
    assert.equal(result.event.tool.input.x > 0, true);
    assert.equal(pulls, 0);
    assert.equal(seen[0].params.event.tool.input.x, 1);
    assert.equal(seen[1].params.event.tool.input.x, 2);
    assert.equal(result.event.tool.input.x, 2);
  } finally {
    await client.close();
  }
});

test("explicit subscriptions require advertised event and mode; wildcards intersect the host manifest", async () => {
  const manifest = {
    authentication: [],
    contentCategories: ["text"],
    correlationIdentityFields: [],
    events: [
      {
        event: "tool.before",
        modes: ["intercept"],
        capabilities: { effects: [] },
      },
    ],
    gaps: [],
    limits: {},
    managedPolicy: { disableable: false, scopes: ["user"] },
    toolPaths: ["*"],
    transports: ["http"],
  };
  function create(subscriptions) {
    const seen = [];
    const client = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "test.manifest",
            transport: { type: "http", url: "https://policy.example/hooks" },
            subscriptions,
          },
        ],
      },
      {
        source: "urn:test:manifest",
        capabilities: manifest,
        fetch: (url, init) =>
          hooks.handle(new Request(url, init), (message) => {
            seen.push(message.method);
            if (message.method === "hooks/intercept") return { effects: [] };
          }),
      },
    );
    return { client, seen };
  }
  const sub = (mode, event) => ({
    mode,
    events: [event],
    content: { default: "metadata" },
    ...(mode === "intercept"
      ? { timeoutMs: 1000, failurePolicy: "fail-open" }
      : {}),
  });
  for (const subscription of [
    sub("observe", "hook.failure"),
    sub("observe", "tool.before"),
    sub("intercept", "tool.after"),
  ]) {
    const { client, seen } = create([subscription]);
    try {
      await assert.rejects(client.initialized, ConfigurationError);
      await assert.rejects(
        client.dispatch("tool.before", tool()),
        ConfigurationError,
      );
      assert.deepEqual(seen, []);
    } finally {
      await client.close();
    }
  }
  const { client, seen } = create([
    sub("observe", "*"),
    sub("intercept", "tool.*"),
  ]);
  try {
    await client.initialized;
    const result = await client.dispatch("tool.before", tool());
    await result.observations;
    assert.deepEqual(result.errors, []);
    assert.deepEqual(seen, ["hooks/intercept"]);
  } finally {
    await client.close();
  }
  manifest.events[0].modes = ["observe"];
  const observeOnly = create([
    sub("observe", "tool.before"),
    sub("intercept", "*"),
  ]);
  try {
    await observeOnly.client.initialized;
    const result = await observeOnly.client.dispatch("tool.before", tool());
    await result.observations;
    assert.deepEqual(result.errors, []);
    assert.deepEqual(observeOnly.seen, ["hooks/observe"]);
  } finally {
    await observeOnly.client.close();
  }
});
