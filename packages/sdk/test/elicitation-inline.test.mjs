import test from "node:test";
import assert from "node:assert/strict";
import {
  readSelectedElicitation,
  validateElicitationExchange,
} from "../dist/src/elicitation.js";

const validate = () => {};
const requestMeta = {
  mode: "form",
  server: "mcp:test",
  request: {
    kind: "text",
    mediaType: "text/plain",
    selection: "body",
    text: JSON.stringify({ message: "Choose", requestedSchema: { type: "object" } }),
  },
};
const request = {
  id: "request",
  params: {
    capabilities: { effects: ["deny"] },
    event: {
      id: "request", type: "user.elicitation.request", source: "test",
      session: { id: "session" }, elicitation: requestMeta,
    },
  },
};

test("selected elicitation bodies use inline JSON without a reference resolver", () => {
  assert.equal(readSelectedElicitation(requestMeta, "request", validate).message, "Choose");
  assert.equal(readSelectedElicitation({ ...requestMeta, request: undefined }, "request", validate), null);
  assert.throws(() => readSelectedElicitation({
    ...requestMeta, request: { ...requestMeta.request, text: undefined, gap: "source_unavailable" },
  }, "request", validate), /Selected text unavailable/);
});

test("exchange validation accepts the canonical inline-only signature", () => {
  const result = {
    id: "result",
    params: {
      event: {
        id: "result", parentEventId: "request", type: "user.elicitation.result",
        source: "test", session: { id: "session" },
        elicitation: {
          mode: "form", server: "mcp:test", action: "decline",
          result: { kind: "text", mediaType: "text/plain", selection: "body", text: '{"action":"decline"}' },
        },
      },
    },
  };
  const exchange = validateElicitationExchange(request, result, validate, "principal");
  assert.equal(exchange.result.action, "decline");
  assert.equal(exchange.provenance.authenticatedSource, "principal");
  const returned = { ...request, params: { ...request.params, capabilities: { effects: ["return"] } } };
  const accepted = validateElicitationExchange(returned, result, validate, "principal", { type: "return", value: { action: "decline", future: { retained: true } } });
  assert.equal(accepted.provenance.effect, "return");
  assert.throws(() => validateElicitationExchange(returned, result, validate, "principal", { type: "return", value: "decline" }), /Invalid contextual elicitation effect/);

});

test("elicitation has no separate effect settlement entrypoint", async () => {
  const sdk = await import("agenthooksprotocol");
  assert.equal("applyElicitationEffects" in sdk, false);
});
