import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Hooks } from "agenthooksprotocol/client";

const returned = { type: "return", value: { action: "decline" } };
const denied = { type: "deny", reason: "Policy" };

async function dispatch(
  effects,
  failurePolicy = "fail-open",
  type = "user.elicitation.request",
  selection = "body",
  modeGrants = { form: {} },
) {
  let deliveries = 0;
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "test.terminals",
          transport: { type: "http", url: "https://hooks.example/intercept" },
          subscriptions: [
            {
              mode: "intercept",
              events: [type],
              timeoutMs: 10000,
              failurePolicy,
              content: { default: selection },
              upload: {
                endpoint: "https://hooks.example/upload",
                timeoutMs: 10000,
                maxBytes: 4096,
              },
            },
          ],
        },
      ],
    },
    {
      source: "urn:test:terminals",
      capabilities: {
        [type]: {
          effects: ["return", "deny", "message"],
          ...(type === "user.elicitation.request"
            ? modeGrants === null
              ? {}
              : { elicitation: modeGrants }
            : {}),
        },
      },
      fetch: async (url, init) => {
        if (String(url).endsWith("/upload")) {
          const bytes = Buffer.from(
            await new Response(init.body).arrayBuffer(),
          );
          return Response.json(
            {
              ref: "urn:test:body",
              size: bytes.length,
              sha256: createHash("sha256").update(bytes).digest("hex"),
            },
            { status: 201 },
          );
        }
        deliveries++;
        const request = JSON.parse(init.body);
        return Response.json({
          jsonrpc: "2.0",
          id: request.id,
          result: { protocolVersion: "draft", effects },
        });
      },
    },
  );
  try {
    const input =
      type === "tool.before"
        ? {
            call: { id: "call" },
            path: "native",
            tool: { name: "test", origin: "native", input: {} },
          }
        : {
            elicitation: {
              mode: "form",
              server: "test",
              request: {
                id: "request",
                kind: "text",
                mediaType: "text/plain",
                selection: "body",
                text: JSON.stringify({
                  message: "Answer?",
                  requestedSchema: { type: "object", properties: {} },
                }),
              },
            },
          };
    const result = await client.dispatch(type, input);
    assert.deepEqual(result.diagnostics.filter(diagnostic => diagnostic.phase === 'observation'), []);
    assert.equal(deliveries, 1);
    return result;
  } finally {
    await client.close();
  }
}

for (const failurePolicy of ["fail-open", "fail-closed"]) {
  for (const effects of [
    [returned, denied],
    [denied, returned],
  ]) {
    test(`elicitation rejects ${effects.map((e) => e.type).join("+")} atomically (${failurePolicy})`, async () => {
      const result = await dispatch(effects, failurePolicy);
      assert.equal(result.diagnostics.filter(d => d.phase !== "observation").length, 1);
      assert.equal(result.diagnostics.filter(d => d.phase !== "observation")[0].code, "protocol_rejection");
      assert.equal(result.diagnostics.filter(d => d.phase !== "observation")[0].phase, "interception");
      assert.equal(
        result.diagnostics.filter(d => d.phase !== "observation")[0].syntheticDenial,
        failurePolicy === "fail-closed",
      );
      assert.deepEqual(
        result.effects,
        failurePolicy === "fail-closed"
          ? [{ type: "deny", reason: "Required policy backend unavailable." }]
          : [],
      );
    });
  }
}

for (const selection of ["metadata", "omit"]) {
  for (const effect of [returned, denied]) {
    test(`elicitation ${effect.type} requires selected body, not ${selection}`, async () => {
      const result = await dispatch(
        [effect],
        "fail-open",
        "user.elicitation.request",
        selection,
      );
      assert.equal(result.diagnostics.filter(d => d.phase !== "observation").length, 1);
      assert.equal(result.diagnostics.filter(d => d.phase !== "observation")[0].code, "protocol_rejection");
      assert.deepEqual(result.effects, []);
    });
  }
}

for (const effect of [returned, denied]) {
  test(`elicitation still accepts a single ${effect.type}`, async () => {
    const result = await dispatch([effect]);
    assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), []);
    assert.deepEqual(result.acceptedResponses[0].result.effects, [effect]);
    assert.deepEqual(result.effects, effect.type === "return" ? [] : [effect]);
    if (effect.type === "return") assert.deepEqual(result.state.candidate.value, effect.value);
  });
}

for (const effects of [
  [returned, denied],
  [denied, returned],
]) {
  test(`tool return/deny precedence remains unchanged (${effects[0].type} first)`, async () => {
    const result = await dispatch(effects, "fail-open", "tool.before");
    assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), []);
    assert.deepEqual(result.effects, [denied]);
  });
}

for (const modeGrants of [null, {}, { url: {} }]) {
  for (const effect of [returned, denied]) {
    test(`elicitation ${effect.type} rejects unsupported AHP mode ${JSON.stringify(modeGrants)}`, async () => {
      const result = await dispatch(
        [effect],
        "fail-open",
        "user.elicitation.request",
        "body",
        modeGrants,
      );
      assert.equal(result.diagnostics.filter(d => d.phase !== "observation").length, 1);
      assert.deepEqual(result.effects, []);
    });
  }
}
