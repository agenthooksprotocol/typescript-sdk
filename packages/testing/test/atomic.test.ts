import test from "node:test";
import assert from "node:assert/strict";
import { runAtomicInterop } from "../src/interop/atomic-client.js";

test("draft tool.before atomic responses: public Hooks exact state and real transport equivalence", async () => {
  const rows = await runAtomicInterop();
  assert.equal(rows.length, 68);
  assert.equal(rows.filter((row) => !row.hostAccepted).length, 8);
  for (const row of rows) {
    assert.equal(row.client, "public-hooks", row.id);
    assert.deepEqual(
      row.effectiveInput,
      row.actual.state.input,
      `${row.id}: no rejected input leaked`,
    );
    assert.deepEqual(
      row.effects
        .filter((effect) => effect.type === "message")
        .map((effect) => effect.text),
      row.actual.emittedMessages,
      `${row.id}: no rejected message leaked`,
    );
    assert.equal(
      JSON.stringify(row.actual.requests).includes("subscriptionId"),
      false,
      row.id,
    );
    if (!row.hostAccepted) {
      // These legacy fixtures encode task > 0 as staging rejection. The SDK
      // accepts the protocol compound; only userland refuses tool execution.
      assert.deepEqual(row.sdkErrors, [], row.id);
      assert.equal(row.actual.failures, 0, row.id);
      assert.equal(row.actual.state.input.task, 0, row.id);
      assert.deepEqual(
        row.actual.actions,
        ["policy", "host-input-rejected"],
        row.id,
      );
      assert.equal(row.actual.executions, 0, row.id);
      assert.equal(
        row.actual.trace.some((step) => step.startsWith("reject:")),
        false,
        row.id,
      );
      assert.ok(row.actual.emittedMessages.length > 0, row.id);
      continue;
    }
    const expected = structuredClone(row.expected);
    // Correlation identifies a boundary occurrence, not an individual receiver.
    // All canonical state, capabilities, effects and host provenance stay exact.
    for (const request of expected.requests) {
      const envelope = request as {
        id: string;
        params: { event: { id: string } };
      };
      envelope.id = "first";
      envelope.params.event.id = "first";
    }
    assert.deepEqual(row.actual, expected, `${row.transport}: ${row.id}`);
    if (
      row.actual.actions.includes("blocked") ||
      row.actual.actions.includes("approval-required")
    ) {
      assert.equal(row.actual.trace.includes("execute"), false, row.id);
      assert.equal(row.actual.executions, 0, row.id);
    }
    assert.equal(row.actual.trace.includes("message:hidden"), false, row.id);
    assert.equal(row.actual.emittedMessages.includes("hidden"), false, row.id);
  }
  assert.deepEqual(
    rows
      .filter((row) => row.transport === "http")
      .map((row) => [row.id, row.actual]),
    rows
      .filter((row) => row.transport === "stdio")
      .map((row) => [row.id, row.actual]),
  );
});
