import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { composeResponse } = await import(
  require.resolve("agenthooksprotocol/client")
);

const envelope = { id: "e", source: "urn:test", time: "2026-01-01T00:00:00Z" };
const tool = () => ({
  ...envelope,
  type: "tool.before",
  call: { id: "c" },
  path: "native",
  tool: {
    name: "read",
    origin: "native",
    input: { path: "a", nested: { a: 1 } },
  },
});
const caps = {
  effects: [
    "modify",
    "return",
    "allow",
    "ask",
    "deny",
    "message",
    "flow",
    "inject",
  ],
  modify: { input: { replace: true, merge: true } },
  flow: { operations: ["stop"] },
  inject: { context: { append: true, deliverAt: ["now", "next_turn"] } },
};
const response = (effects) => ({
  jsonrpc: "2.0",
  id: "e",
  result: { protocolVersion: "draft", effects },
});
const compose = (event, previous, effects, capabilities = caps) =>
  composeResponse(event, previous, response(effects), capabilities);

test("tool composition is atomic, object input is not a synthetic task fixture", () => {
  const event = tool();
  const first = compose(
    event,
    [],
    [
      { type: "return", value: "cached" },
      {
        type: "modify",
        target: "input",
        operation: "merge",
        value: { path: "b", nested: null },
      },
      { type: "allow" },
    ],
  );
  assert.deepEqual(first.event.tool.input, { path: "b", nested: null });
  assert.equal(first.state.candidate.value, "cached");
  assert.equal(first.state.permission, "allow");
  const second = compose(first.event, first.effects, [
    {
      type: "modify",
      target: "input",
      operation: "replace",
      value: { path: "c" },
    },
  ]);
  assert.equal(second.state.candidate, null);
  assert.equal(second.state.permission, "none");
  assert.ok(
    !second.effects.some((e) => e.type === "return" || e.type === "allow"),
  );
  assert.deepEqual(event, tool());
  assert.throws(() =>
    compose(first.event, first.effects, [
      { type: "deny", reason: "no" },
      { type: "future" },
    ]),
  );
  assert.equal(first.state.candidate.value, "cached");
});

test("no-op mutations retain authorization and candidates; ask persists", () => {
  const first = compose(
    tool(),
    [],
    [{ type: "return", value: 1 }, { type: "allow" }],
  );
  const next = compose(first.event, first.effects, [
    { type: "modify", target: "input", operation: "merge", value: {} },
  ]);
  assert.equal(next.state.permission, "allow");
  assert.equal(next.state.candidate.value, 1);
  const ask = compose(next.event, next.effects, [
    { type: "ask" },
    { type: "allow" },
  ]);
  assert.equal(ask.state.permission, "ask");
  const deny = compose(ask.event, ask.effects, [
    { type: "deny", reason: "no" },
  ]);
  assert.equal(deny.state.candidate, null);
  assert.equal(deny.shortCircuit, true);
});

test("boundary restrictions override overly broad advertisements", () => {
  assert.throws(() =>
    compose(
      { ...envelope, type: "config.change.before" },
      [],
      [{ type: "allow" }],
      { effects: ["allow"] },
    ),
  );
  assert.throws(() =>
    compose(
      tool(),
      [],
      [{ type: "modify", target: "output", operation: "replace", value: [] }],
    ),
  );
  assert.throws(() =>
    compose(
      tool(),
      [],
      [{ type: "modify", target: "input", operation: "replace", value: "bad" }],
    ),
  );
});

test("continuation instructions accumulate once and stop discards candidate work", () => {
  const event = { ...envelope, type: "turn.finish.before" };
  const capabilities = {
    effects: ["flow", "message"],
    flow: {
      operations: ["continue", "stop"],
      remainingContinuations: 1,
      maxContinuations: 2,
      continuationCount: 1,
    },
  };
  const first = compose(
    event,
    [],
    [
      { type: "flow", operation: "continue", instruction: "one" },
      { type: "message", text: "hello" },
    ],
    capabilities,
  );
  const next = compose(
    event,
    first.effects,
    [{ type: "flow", operation: "continue", instruction: "two" }],
    capabilities,
  );
  assert.deepEqual(next.state.instructions, ["one", "two"]);
  const stop = compose(
    event,
    next.effects,
    [{ type: "flow", operation: "stop", reason: "done" }],
    capabilities,
  );
  assert.equal(stop.state.flow, "stop");
  assert.equal(stop.shortCircuit, true);
  assert.throws(() =>
    compose(
      event,
      [],
      [
        { type: "message", text: "no publication" },
        { type: "flow", operation: "continue" },
      ],
      {
        ...capabilities,
        flow: { ...capabilities.flow, remainingContinuations: 0 },
      },
    ),
  );
});

test("raw stream references survive unrelated modifications and injection staging", () => {
  const body = new ReadableStream();
  const event = {
    ...tool(),
    items: [
      {
        id: "item",
        kind: "attachment",
        mediaType: "application/octet-stream",
        selection: "body",
        body,
      },
    ],
  };
  const result = compose(
    event,
    [],
    [
      {
        type: "modify",
        target: "input",
        operation: "merge",
        value: { path: "changed" },
      },
      {
        type: "inject",
        target: "context",
        operation: "append",
        deliverAt: "next_turn",
        value: [message("context", "context")],
      },
    ],
  );
  assert.equal(result.event.items[0].body, body);
  assert.equal(result.state.injections[0].deliverAt, "next_turn");
  assert.equal(body.locked, false);
});

test("model request modifications use canonical message lists", () => {
  const model = {
    ...envelope,
    type: "model.request.before",
    items: [],
    params: { temperature: 1 },
    attempt: { id: "a", number: 1 },
    model: { id: "m", provider: "test" },
  };
  const modified = compose(
    model,
    [],
    [
      {
        type: "modify",
        target: "request",
        operation: "merge",
        value: [message("request", "new prompt")],
      },
    ],
    {
      effects: ["modify"],
      modify: { request: { replace: false, merge: true } },
    },
  );
  assert.equal(modified.event.params.temperature, 1);
  assert.equal(modified.event.items[0].parts[0].text, "new prompt");
  assert.equal(modified.event.request, undefined);
});

const { composeResponseAsync } = await import(
  require.resolve("agenthooksprotocol/client")
);
const textPart = (id, value) => ({
  id, kind: "text", mediaType: "text/plain", selection: "body",
  text: typeof value === "string" ? value : JSON.stringify(value),
});
const message = (id, value, role = "user") => ({
  id, role, parts: [textPart(`${id}-text`, value)],
});
const bodyReader = () => {
  const snapshots = new WeakMap();
  return async (body) => {
    if (!snapshots.has(body))
      snapshots.set(
        body,
        (async () => new Uint8Array(await new Response(body).arrayBuffer()))(),
      );
    return (await snapshots.get(body)).slice();
  };
};
const readText = async (item) => item.text;
const modifyCaps = (target) => ({
  effects: ["modify"],
  modify: { [target]: { replace: true, merge: true } },
});

test("async compaction rewrites inline text into identity-preserving parts", async () => {
  const instructions = [textPart("instructions", "original")];
  instructions[0].sha256 = "0".repeat(64);
  const event = {
    ...envelope,
    type: "context.compact.before",
    trigger: "manual",
    items: [],
    instructions,
  };
  const result = await composeResponseAsync(
    event,
    [],
    response([
      {
        type: "modify",
        target: "instructions",
        operation: "replace",
        value: [textPart("instructions", "new instructions")],
      },
    ]),
    modifyCaps("instructions"),
    { readContent: bodyReader() },
  );
  assert.equal(result.event.instructions[0].id, "instructions");
  assert.equal(result.event.instructions[0].sha256, undefined);
  assert.equal(result.event.instructions[0].text.length, 16);
  assert.equal(await readText(result.event.instructions[0]), "new instructions");
  assert.equal(event.instructions, instructions);
  const after = {
    ...envelope,
    type: "context.compact.after",
    summary: [textPart("summary", "old")],
    removed: [],
    execution: { status: "executed" },
  };
  const summary = await composeResponseAsync(
    after,
    [],
    response([
      {
        type: "modify",
        target: "summary",
        operation: "replace",
        value: [textPart("summary", "replacement summary")],
      },
    ]),
    modifyCaps("summary"),
    { readContent: bodyReader() },
  );
  assert.equal(summary.event.summary[0].id, "summary");
  assert.equal(await readText(summary.event.summary[0]), "replacement summary");
});

test("async output list modifications chain and append JSON text messages", async () => {
  const event = {
    ...tool(),
    type: "tool.after",
    items: [message("out", { a: 1, nested: { old: true } }, "tool")],
    outcome: "ok",
    execution: { status: "executed" },
  };
  const effects = [
    {
      type: "modify",
      target: "output",
      operation: "merge",
      value: [message("next", { nested: null }, "tool")],
    },
    { type: "modify", target: "output", operation: "merge", value: [message("last", { b: 2 }, "tool")] },
  ];
  const result = await composeResponseAsync(
    event,
    [],
    response(effects),
    modifyCaps("output"),
    { readContent: bodyReader() },
  );
  assert.deepEqual(result.event.items.map(item => JSON.parse(item.parts[0].text)), [
    { a: 1, nested: { old: true } }, { nested: null }, { b: 2 },
  ]);
  assert.deepEqual(result.effects, effects);
  assert.equal(result.event.items[0].id, "out");
});

test("async prompt and model response materialization preserve catalogue locations", async () => {
  const event = {
    ...envelope,
    type: "user.message.inbound",
    message: {
      sender: "person",
      channel: "chat",
      messages: [message("prompt", "old")],
    },
  };
  const result = await composeResponseAsync(
    event,
    [],
    response([
      { type: "modify", target: "prompt", operation: "replace", value: [message("prompt", "new", "user")] },
    ]),
    modifyCaps("prompt"),
    { readContent: bodyReader() },
  );
  assert.equal(await readText(result.event.message.messages[0].parts[0]), "new");
  assert.equal(result.event.message.messages[0].id, "prompt");
  const model = {
    ...envelope,
    type: "model.response.after",
    items: [message("answer", "old", "assistant")],
    model: { id: "model", provider: "test" },
    attempt: { id: "attempt", number: 1 },
    execution: { status: "executed" },
    finishReason: "stop",
  };
  const modified = await composeResponseAsync(
    model,
    [],
    response([
      {
        type: "modify",
        target: "response",
        operation: "replace",
        value: [message("answer", "answer", "assistant")],
      },
    ]),
    modifyCaps("response"),
    { readContent: bodyReader() },
  );
  assert.equal(await readText(modified.event.items[0].parts[0]), "answer");
});

const formRequest = () => ({
  ...envelope,
  id: "request",
  type: "user.elicitation.request",
  elicitation: {
    mode: "form",
    server: "mcp",
    request: textPart("request-body", {
      message: "Name?",
      requestedSchema: {
        type: "object",
        properties: {
          name: { type: "string", minLength: 2 },
          age: { type: "integer", minimum: 0 },
        },
        required: ["name"],
      },
    }),
  },
});
test("async elicitation accepts validated forms and rejects invalid submitted values", async () => {
  const event = formRequest();
  const capabilities = { effects: ["return"], elicitation: { form: {} } };
  const options = { readContent: bodyReader() };
  const result = await composeResponseAsync(
    event,
    [],
    response([
      {
        type: "return",
        value: { action: "accept", content: { name: "Alice", age: 3 } },
      },
    ]),
    capabilities,
    options,
  );
  assert.deepEqual(result.state.candidate.value, {
    action: "accept",
    content: { name: "Alice", age: 3 },
  });
  await assert.rejects(
    composeResponseAsync(
      event,
      [],
      response([
        { type: "return", value: { action: "accept", content: { name: "A" } } },
      ]),
      capabilities,
      options,
    ),
    /requestedSchema/,
  );
  assert.equal(
    result.event.elicitation.request.text,
    event.elicitation.request.text,
  );
});

test("async elicitation result content rewrites the MCP body, not the descriptor", async () => {
  const request = formRequest();
  const event = {
    ...envelope,
    type: "user.elicitation.result",
    parentEventId: "request",
    elicitation: {
      server: "mcp",
      mode: "form",
      action: "accept",
      result: textPart("answer-body", {
        action: "accept",
        content: { name: "Alice", age: 3 },
        _meta: { preserved: true },
      }),
    },
  };
  const capabilities = { ...modifyCaps("content"), elicitation: { form: {} } };
  const options = { readContent: bodyReader(), elicitationRequest: request };
  const result = await composeResponseAsync(
    event,
    [],
    response([
      {
        type: "modify",
        target: "content",
        operation: "merge",
        value: { age: 4 },
      },
    ]),
    capabilities,
    options,
  );
  const answer = JSON.parse(await readText(result.event.elicitation.result));
  assert.deepEqual(answer, {
    action: "accept",
    content: { name: "Alice", age: 4 },
    _meta: { preserved: true },
  });
  assert.equal(result.event.elicitation.result.id, "answer-body");
  assert.equal(result.event.elicitation.action, "accept");
  await assert.rejects(
    composeResponseAsync(
      event,
      [],
      response([
        {
          type: "modify",
          target: "content",
          operation: "replace",
          value: { age: 4 },
        },
      ]),
      capabilities,
      options,
    ),
    /requestedSchema/,
  );
});

test("async rejection precedes body reads and never publishes partial changes", async () => {
  let reads = 0;
  const event = formRequest();
  await assert.rejects(
    composeResponseAsync(
      event,
      [],
      response([
        {
          type: "return",
          value: { action: "accept", content: { name: "Alice" } },
        },
        { type: "future" },
      ]),
      { effects: ["return"], elicitation: { form: {} } },
      {
        readContent: async () => {
          reads++;
          return new Uint8Array();
        },
      },
    ),
  );
  assert.equal(reads, 0);
  assert.equal(event.elicitation.request.text, formRequest().elicitation.request.text);
});

test("metadata-only projections never cause body-dependent reads", async () => {
  const event = formRequest();
  const selectedEvent = {
    ...event,
    elicitation: {
      ...event.elicitation,
      request: {
        id: "request-body",
        kind: "text",
        mediaType: "text/plain",
        selection: "metadata",
      },
    },
  };
  let reads = 0;
  await assert.rejects(
    composeResponseAsync(
      event,
      [],
      response([{ type: "return", value: { action: "decline" } }]),
      { effects: ["return"], elicitation: { form: {} } },
      {
        selectedEvent,
        readContent: async () => {
          reads++;
          return new Uint8Array();
        },
      },
    ),
    /selected body/,
  );
  assert.equal(reads, 0);
  const output = {
    ...tool(),
    type: "tool.after",
    items: [message("out", { a: 1 }, "tool")],
    outcome: "ok",
    execution: { status: "executed" },
  };
  const selectedOutput = {
    ...output,
    items: [
      {
        id: "out",
        role: "tool",
        parts: [{ id: "out-text", kind: "text", mediaType: "text/plain", selection: "metadata" }],
      },
    ],
  };
  const options = {
    selectedEvent: selectedOutput,
    readContent: async () => {
      reads++;
      return new Uint8Array();
    },
  };
  await assert.rejects(
    composeResponseAsync(
      output,
      [],
      response([
        {
          type: "modify",
          target: "output",
          operation: "merge",
          value: { a: 2 },
        },
      ]),
      modifyCaps("output"),
      options,
    ),
    /Invalid intercept response/,
  );
  const replaced = await composeResponseAsync(
    output,
    [],
    response([
      {
        type: "modify",
        target: "output",
        operation: "replace",
        value: [message("out", "public replacement", "tool")],
      },
    ]),
    modifyCaps("output"),
    options,
  );
  assert.equal(await readText(replaced.event.items[0].parts[0]), "public replacement");
  assert.equal(reads, 0);
});

test("URL elicitation accepts consent, forbids content, and preserves correlation", async () => {
  const request = {
    ...envelope,
    id: "url-request",
    type: "user.elicitation.request",
    elicitation: {
      mode: "url",
      server: "mcp",
      request: textPart("url", {
        mode: "url",
        message: "Open consent page",
        url: "https://example.test/consent",
        elicitationId: "opaque",
      }),
    },
  };
  const capabilities = { effects: ["return"], elicitation: { url: {} } };
  const options = { readContent: bodyReader() };
  const accepted = await composeResponseAsync(
    request,
    [],
    response([{ type: "return", value: { action: "accept" } }]),
    capabilities,
    options,
  );
  assert.deepEqual(accepted.state.candidate.value, { action: "accept" });
  await assert.rejects(
    composeResponseAsync(
      request,
      [],
      response([{ type: "return", value: { action: "accept", content: {} } }]),
      capabilities,
      options,
    ),
    /content/,
  );
  const wrong = {
    ...envelope,
    parentEventId: "wrong",
    type: "user.elicitation.result",
    elicitation: {
      mode: "url",
      server: "mcp",
      action: "accept",
      result: textPart("result", { action: "accept" }),
    },
  };
  await assert.rejects(
    composeResponseAsync(
      wrong,
      [],
      response([
        { type: "modify", target: "content", operation: "replace", value: {} },
      ]),
      { ...modifyCaps("content"), elicitation: { url: {} } },
      { ...options, elicitationRequest: request },
    ),
    /correlation/,
  );
});

test("normalized model request rewrites messages without fabricating params or usage", async () => {
  const event = {
    ...envelope,
    type: "model.request.before",
    items: [message("prompt", "old")],
    params: { temperature: 1 },
    attempt: { id: "a", number: 1 },
    model: { id: "m", provider: "test" },
  };
  const effects = [
    {
      type: "modify",
      target: "request",
      operation: "replace",
      value: [message("prompt", "new prompt")],
    },
  ];
  const result = await composeResponseAsync(
    event,
    [],
    response(effects),
    modifyCaps("request"),
    { readContent: bodyReader() },
  );
  assert.deepEqual(result.event.params, { temperature: 1 });
  assert.equal(await readText(result.event.items[0].parts[0]), "new prompt");
  assert.equal(result.event.items[0].id, "prompt");
  assert.deepEqual(result.event.model, event.model);
  assert.equal(result.event.usage, undefined);
});

test("identical inline compaction modification preserves an existing candidate", async () => {
  const event = {
    ...envelope,
    type: "context.compact.before",
    trigger: "manual",
    items: [],
    instructions: [textPart("instructions", "same")],
  };
  const effects = [
    {
      type: "modify",
      target: "instructions",
      operation: "replace",
      value: [textPart("instructions", "same")],
    },
  ];
  const result = await composeResponseAsync(
    event,
    [{ type: "return", value: "summary" }],
    response(effects),
    modifyCaps("instructions"),
    { readContent: bodyReader() },
  );
  assert.equal(result.state.candidate.value, "summary");
  assert.equal(result.event.instructions[0].text, event.instructions[0].text);
});
