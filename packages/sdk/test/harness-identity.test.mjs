import test from "node:test";
import assert from "node:assert/strict";
import { Hooks, ConfigurationError } from "agenthooksprotocol/client";
import {
  draftCodecs,
  validateInterceptRequest,
  validateObserveNotification,
} from "agenthooksprotocol/draft";

const validateDelivery = (request) =>
  request.method === "hooks/intercept"
    ? validateInterceptRequest(request)
    : validateObserveNotification(request);

const identity = { name: "test-agent", version: "1.2.3" };
const config = {
  protocolVersion: "draft",
  hooks: [
    {
      id: "identity.backend",
      transport: { type: "http", url: "https://hooks.example/events" },
      subscriptions: [
        {
          mode: "intercept",
          events: ["tool.before"],
          timeoutMs: 1000,
          failurePolicy: "fail-closed",
          content: { default: "metadata" },
        },
        {
          mode: "observe",
          events: ["session.start", "turn.start"],
          content: { default: "metadata" },
        },
      ],
    },
  ],
};
const capabilities = {
  toolBefore: { intercept: { deny: true } },
  sessionStart: { observe: true },
  turnStart: { observe: true },
};
function client(harness = structuredClone(identity), deliveries = []) {
  return new Hooks(config, {
    source: "urn:test:identity",
    harness,
    capabilities,
    fetch: async (_url, init) => {
      const request = JSON.parse(init.body);
      deliveries.push(request);
      return request.method === "hooks/intercept"
        ? new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: request.id,
              result: { protocolVersion: "draft", effects: [] },
            }),
          )
        : new Response(null, { status: 204 });
    },
  });
}
const toolInput = {
  callId: "call",
  path: "native",
  name: "read_file",
  origin: "native",
  input: {},
};

test("constructor requires a canonical harness identity", () => {
  for (const harness of [
    undefined,
    null,
    {},
    { name: "agent" },
    { version: "1" },
    { name: "", version: "1" },
    { name: "agent", version: "" },
    { name: 1, version: "1" },
    { name: "agent", version: 1 },
    { ...identity, extra: true },
    [],
  ]) {
    assert.throws(
      () =>
        new Hooks(config, {
          source: "urn:test:identity",
          harness,
          capabilities,
        }),
      ConfigurationError,
    );
  }
});

test("every intercept and observation carries the detached configured identity", async () => {
  const harness = structuredClone(identity);
  const deliveries = [];
  const hooks = client(harness, deliveries);
  harness.name = "mutated";
  harness.version = "99";
  try {
    const result = await hooks.toolBefore(toolInput);
    result.event.harness.name = "mutated-result";
    await hooks.sessionStart({
      session: { id: "session" },
      trigger: "startup",
      permissionMode: "default",
      items: [],
    });
    await hooks.turnStart({ turn: { id: "turn" }, trigger: "user", items: [] });
    assert.deepEqual(
      deliveries.map((request) => request.params.event.type),
      ["tool.before", "session.start", "turn.start"],
    );
    for (const request of deliveries) {
      assert.deepEqual(request.params.event.harness, identity);
      assert.equal(validateDelivery(request).ok, true);
      assert.equal(draftCodecs.parseEvent(request.params.event).ok, true);
    }
  } finally {
    await hooks.close();
  }
});

test("full-event dispatch verifies identity before replacing it with a detached snapshot", async () => {
  const deliveries = [];
  const hooks = client(structuredClone(identity), deliveries);
  try {
    await hooks.toolBefore(toolInput);
    const event = structuredClone(deliveries[0].params.event);
    await hooks.dispatch("tool.before", event);
    assert.deepEqual(deliveries[1].params.event.harness, identity);
    event.harness.name = "different";
    await assert.rejects(
      hooks.dispatch("tool.before", event),
      ConfigurationError,
    );
    event.harness = { ...identity, version: "different" };
    await assert.rejects(
      hooks.dispatch("tool.before", event),
      ConfigurationError,
    );
    event.harness = { ...identity, extra: true };
    await assert.rejects(
      hooks.dispatch("tool.before", event),
      ConfigurationError,
    );
    assert.equal(deliveries.length, 2);
  } finally {
    await hooks.close();
  }
});

test("wire event validators require canonical harness on every delivered event", async () => {
  const deliveries = [];
  const hooks = client(structuredClone(identity), deliveries);
  try {
    await hooks.toolBefore(toolInput);
    await hooks.turnStart({ turn: { id: "turn" }, trigger: "user", items: [] });
    for (const request of deliveries) {
      const wire = structuredClone(request);
      const event = wire.params.event;
      for (const malformed of [
        undefined,
        {},
        { name: "", version: "1" },
        { name: "agent", version: "" },
      ]) {
        if (malformed === undefined) delete event.harness;
        else event.harness = malformed;
        assert.equal(validateDelivery(wire).ok, false);
        if (malformed === undefined || Object.keys(malformed).length === 0)
          assert.equal(draftCodecs.parseEvent(event).ok, false);
      }
    }
  } finally {
    await hooks.close();
  }
});
