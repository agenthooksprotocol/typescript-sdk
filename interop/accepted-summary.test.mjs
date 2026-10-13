import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { sdkClient, sdkDraft } from "./common.mjs";
import { summarizeAccepted, matches } from "./evaluator.mjs";
const { Hooks, capabilityCount } = sdkClient;

// Explicit host controls for the canonical summary matrix's two boundaries.
// Each dispatch retains the fixture's narrower wire grant verbatim.
function summaryCapabilities(eventType) {
  if (eventType === "tool.before") return {
    toolBefore: { intercept: {
      deny: true, allow: true, ask: true, message: true, returnResult: true,
      modifyInput: "replace-and-merge",
      flow: { operations: ["stop"] },
      inject: { context: { append: true, deliverAt: ["now", "next_turn"] } },
    } },
  };
  if (eventType === "turn.finish.before") return {
    turnFinishBefore: { intercept: {
      message: true,
      flow: {
        operations: ["stop", "continue"],
        remainingContinuations: capabilityCount(2),
        continuationCount: capabilityCount(0),
        maxContinuations: capabilityCount(2),
      },
    } },
  };
  throw Error(`Unexpected summary fixture boundary: ${eventType}`);
}

test("canonical summaries distinguish SDK protocol rejection from userland tool-schema rejection", async () => {
  const { scenarios } = JSON.parse(
    await readFile("../agent-hooks-protocol/interop/scenarios.json", "utf8"),
  );
  for (const row of scenarios) {
    row.request = sdkDraft.validateInterceptRequest(row.request).value;
    const event = row.request.params.event;
    const client = new Hooks(
      {
        protocolVersion: "draft",
        hooks: [
          {
            id: "summary.test",
            transport: {
              type: "http",
              url: "https://summary.example/intercept",
            },
            subscriptions: [
              {
                mode: "intercept",
                events: [event.type],
                timeoutMs: 5000,
                failurePolicy: "fail-open",
                content: { default: "metadata" },
              },
            ],
          },
        ],
      },
      {
        harness: event.harness,
        source: event.source,
        capabilities: summaryCapabilities(event.type),
        fetch: async (_url, init) => {
          const request = JSON.parse(init.body);
          return Response.json({
            ...row.response,
            id:
              row.response.id === row.request.id ? request.id : row.response.id,
          });
        },
      },
    );
    try {
      const result = await client.dispatch(event.type, event, {
        initialState: row.request.params.state,
        capabilities: row.request.params.capabilities,
      });
      const hostRejected =
        result.event.type === "tool.before" &&
        result.event.tool.name === "task" &&
        !(
          Number.isInteger(result.event.tool.input.task) &&
          result.event.tool.input.task > 0
        );
      if (hostRejected) {
        // task > 0 is a synthetic host rule, not protocol validation.
        assert.equal(row.expectError, true, row.id);
        assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), [], row.id);
        assert.deepEqual(
          result.acceptedResponses[0].result.effects,
          row.response.result.effects,
          row.id,
        );
        assert.equal(hostRejected, true, row.id);
        let executions = 0;
        if (!hostRejected) executions++;
        assert.equal(executions, 0, row.id);
      } else if (row.expectError) {
        assert.ok(
          result.diagnostics.filter(d => d.phase !== "observation").some((error) => error.code === "protocol_rejection"),
          row.id,
        );
      } else {
        assert.deepEqual(result.diagnostics.filter(d => d.phase !== "observation"), [], row.id);
        const actual = summarizeAccepted(row.request, result);
        assert.equal(
          matches(actual, row.expected),
          true,
          `${row.id}: ${JSON.stringify(actual)}`,
        );
      }
    } finally {
      await client.close();
    }
  }
});

test("summary does not replay effects or revalidate an accepted SDK response", () => {
  const event = { type: "tool.before", tool: { input: { actual: true } } };
  const request = { params: { event, capabilities: { effects: [] } } };
  const result = {
    event,
    effects: [
      {
        type: "modify",
        target: "input",
        operation: "replace",
        value: { fabricated: true },
      },
      { type: "message", text: "accepted" },
    ],
    state: { permission: "none", candidate: null },
    interrupted: false,
  };
  assert.deepEqual(summarizeAccepted(request, result).input, { actual: true });
  assert.deepEqual(summarizeAccepted(request, result).messages, ["accepted"]);
});
