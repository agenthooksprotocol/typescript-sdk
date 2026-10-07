import test from "node:test";
import assert from "node:assert/strict";
import {
  Hooks,
  Permission,
  state,
  effects,
  ContentSource,
} from "agenthooksprotocol/client";
import { effects as serverEffects } from "agenthooksprotocol/server";

const facts = {
  callId: "c",
  name: "read",
  input: { path: "app-owned" },
  path: "native",
  origin: "native",
};
function hooks(
  fetch,
  capabilities = {
    effects: ["allow", "modify"],
    modify: { input: { replace: true, merge: false } },
  },
) {
  return new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "test.ergonomic",
          transport: { type: "http", url: "https://example.test/hooks" },
          subscriptions: [
            {
              mode: "intercept",
              events: ["tool.before"],
              timeoutMs: 10000,
              failurePolicy: "fail-closed",
              content: { default: "metadata" },
            },
          ],
        },
      ],
    },
    {
      source: "urn:test:ergonomic",
      capabilities: { "tool.before": capabilities },
      fetch,
    },
  );
}

test("named boundaries project generated flattened host facts into canonical wire requests", async () => {
  let wire;
  const client = hooks(async (_, init) => {
    wire = JSON.parse(init.body);
    return Response.json({
      jsonrpc: "2.0",
      id: wire.id,
      result: {
        protocolVersion: "draft",
        effects: [
          serverEffects.modify_input.replace({ path: "accepted" }),
          effects.allow(),
        ],
      },
    });
  });
  try {
    const result = await client.toolBefore({
      ...facts,
      id: "event",
      callSynthesized: false,
      parentEventId: "parent",
    });
    const event = wire.params.event;
    assert.deepEqual(event.call, { id: "c", synthesized: false });
    assert.deepEqual(event.tool, {
      name: "read",
      input: facts.input,
      origin: "native",
    });
    assert.equal(event.path, "native");
    assert.equal(event.parentEventId, "parent");
    assert.equal(event.source, "urn:test:ergonomic");
    assert.equal(event.id, "event");
    assert.equal(event.type, "tool.before");
    assert.equal("callId" in event, false);
    assert.equal("name" in event, false);
    assert.equal(result.permission, Permission.Allow);
    assert.deepEqual(result.input, { path: "accepted" });
    assert.deepEqual(facts.input, { path: "app-owned" });
  } finally {
    await client.close();
  }
});

test("generated initial state distinguishes no candidate from a JSON-null candidate", async () => {
  assert.deepEqual(state.initial(Permission.None), {
    candidate: null,
    permission: "none",
  });
  const supplied = state.initial(Permission.Allow, {
    candidate: state.candidate(null),
  });
  assert.deepEqual(supplied, {
    candidate: { value: null },
    permission: "allow",
  });
  let wire;
  const client = hooks(async (_, init) => {
    wire = JSON.parse(init.body);
    return Response.json({
      jsonrpc: "2.0",
      id: wire.id,
      result: { protocolVersion: "draft", effects: [] },
    });
  });
  try {
    const result = await client.toolBefore(facts, { initialState: supplied });
    assert.deepEqual(wire.params.state, supplied);
    assert.equal(result.state.candidate.value, null);
    assert.equal(result.permission, Permission.Allow);
  } finally {
    await client.close();
  }
});

test("named generated inputs bind lazy sources without manual content paths", async () => {
  let reads = 0,
    cancelled = 0,
    wire;
  const source = new ContentSource(
    new ReadableStream(
      {
        pull() {
          reads++;
        },
        cancel() {
          cancelled++;
        },
      },
      { highWaterMark: 0 },
    ),
  );
  const client = hooks(async (_, init) => {
    wire = JSON.parse(init.body);
    return Response.json({
      jsonrpc: "2.0",
      id: wire.id,
      result: { protocolVersion: "draft", effects: [] },
    });
  });
  try {
    await client.toolBefore({
      ...facts,
      items: [
        { id: "content", kind: "text", mediaType: "text/plain", body: source },
      ],
    });
    assert.equal(wire.params.event.items[0].selection, "metadata");
    assert.equal("body" in wire.params.event.items[0], false);
    assert.equal(reads, 0);
    assert.equal(cancelled, 1);
  } finally {
    await client.close();
  }
});

import {
  capabilities,
  events,
  contentSlots,
} from "agenthooksprotocol/client";
import { createHash } from "node:crypto";

test("generated declarations are immutable, explicit and boundary-compatible", async () => {
  const base = capabilities.intercept().deny();
  const composed = base.modifyInput({ replace: true });
  assert.deepEqual(base.capabilities.effects, ["deny"]);
  assert.deepEqual(composed.modes, ["intercept", "observe"]);
  assert.deepEqual(composed.capabilities.modify.input, {
    merge: false,
    replace: true,
  });
  assert.throws(() => capabilities.intercept().build(), /empty/);
  assert.throws(() => base.modifyInput({}), /nonempty/);
  let deliveries = 0;
  const client = hooks(async (_, init) => {
    deliveries++;
    const request = JSON.parse(init.body);
    assert.deepEqual(request.params.capabilities.effects, ["deny"]);
    return Response.json({
      jsonrpc: "2.0",
      id: request.id,
      result: { protocolVersion: "draft", effects: [] },
    });
  }, composed);
  try {
    await client.toolBefore(facts, { capabilities: base.capabilities });
    assert.equal(deliveries, 1);
    await assert.rejects(
      client.toolBefore(facts, {
        capabilities: capabilities.intercept().allow().capabilities,
      }),
    );
    assert.equal(deliveries, 1, "narrowing cannot widen before delivery");
  } finally {
    await client.close();
  }
  const incompatible = hooks(
    async () => {
      throw new Error("must not deliver");
    },
    capabilities.intercept().modifySummary({ replace: true }),
  );
  try {
    await assert.rejects(incompatible.toolBefore(facts));
  } finally {
    await incompatible.close();
  }
  assert.equal(events.toolBefore, "tool.before");
  assert.deepEqual(capabilities.observe(), { modes: ["observe"] });
  assert.equal(
    "elicitation" in capabilities.intercept().return().capabilities,
    false,
  );
  assert.deepEqual(
    capabilities.intercept().return().elicitationForm().capabilities
      .elicitation,
    { form: {} },
  );
});

test("named source binding prepares receiver references from descriptors without caller refs", async () => {
  let reads = 0;
  const bytes = new TextEncoder().encode("owned binary\u0000payload");
  const source = new ContentSource(
    new ReadableStream(
      {
        pull(controller) {
          reads++;
          controller.enqueue(bytes);
          controller.close();
        },
      },
      { highWaterMark: 0 },
    ),
  );
  const descriptor = {
    id: "content",
    kind: "text",
    mediaType: "text/plain",
    selection: "metadata",
  };
  const requests = [],
    uploads = [];
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "test.source-binding",
          transport: { type: "http", url: "https://example.test/hooks" },
          subscriptions: ["body", "metadata"].map((mode) => ({
            mode: "intercept",
            events: ["tool.before"],
            timeoutMs: 10000,
            failurePolicy: "fail-closed",
            content: { default: mode },
            ...(mode === "body"
              ? {
                  upload: {
                    endpoint: "https://example.test/upload",
                    maxBytes: 1024,
                    timeoutMs: 10000,
                  },
                }
              : {}),
          })),
        },
      ],
    },
    {
      source: "urn:test:source-binding",
      capabilities: { [events.toolBefore]: capabilities.intercept().deny() },
      fetch: async (url, init) => {
        if (url.endsWith("/upload")) {
          const actual = new Uint8Array(
            await new Response(init.body).arrayBuffer(),
          );
          uploads.push(actual);
          return Response.json(
            {
              ref: "urn:receiver:allocated",
              size: actual.length,
              sha256: createHash("sha256").update(actual).digest("hex"),
            },
            { status: 201 },
          );
        }
        const wire = JSON.parse(init.body);
        requests.push(wire);
        return Response.json({
          jsonrpc: "2.0",
          id: wire.id,
          result: { protocolVersion: "draft", effects: [] },
        });
      },
    },
  );
  try {
    const result = await client.toolBefore(
      { ...facts, items: [descriptor] },
      { contentSources: [contentSlots[events.toolBefore].items(0, source)] },
    );
    assert.deepEqual(result.diagnostics, []);
    assert.equal(reads, 1);
    assert.equal(uploads.length, 1);
    assert.deepEqual(uploads[0], bytes);
    assert.equal(
      requests[0].params.event.items[0].body.ref,
      "urn:receiver:allocated",
    );
    assert.equal(requests[0].params.event.items[0].selection, "body");
    assert.equal(requests[1].params.event.items[0].selection, "metadata");
    assert.equal("body" in requests[1].params.event.items[0], false);
    assert.equal(
      "body" in descriptor,
      false,
      "producer descriptor is not mutated",
    );
  } finally {
    await client.close();
  }
});

for (const mode of ["metadata", "omit"])
  test(`named source binding remains unread for ${mode} delivery`, async () => {
    let reads = 0,
      cancelled = 0;
    const source = new ContentSource(
      new ReadableStream(
        {
          pull() {
            reads++;
          },
          cancel() {
            cancelled++;
          },
        },
        { highWaterMark: 0 },
      ),
    );
    const client = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "test.source-unused",
            transport: { type: "http", url: "https://example.test/hooks" },
            subscriptions: [
              {
                mode: "observe",
                events: ["tool.before"],
                content: { default: mode },
              },
            ],
          },
        ],
      },
      {
        source: "urn:test:source-unused",
        capabilities: { [events.toolBefore]: capabilities.observe() },
        fetch: async () => new Response(null, { status: 204 }),
      },
    );
    try {
      await client.toolBefore(
        {
          ...facts,
          items: [
            {
              id: "content",
              kind: "text",
              mediaType: "text/plain",
              selection: "metadata",
            },
          ],
        },
        { contentSources: [contentSlots[events.toolBefore].items(0, source)] },
      );
      assert.equal(reads, 0);
      assert.equal(cancelled, 1);
    } finally {
      await client.close();
    }
  });
