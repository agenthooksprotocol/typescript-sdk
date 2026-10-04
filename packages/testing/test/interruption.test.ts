import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { Capabilities, Effect } from "@agenthooksprotocol/sdk/client";
import {
  DecisionPipeline,
  type HostState,
} from "../src/interop/interruption-pipeline.js";
import { openInterruptionTransport } from "../src/interop/interruption-transport.js";
import { barrier } from "../src/interop/interruption-server.js";

const initial = {
  input: { task: 1 },
  candidate: null,
  permission: "native",
  approval: "not-required",
  denied: false,
  messages: [],
} satisfies HostState;
const capabilities: Capabilities = {
  effects: ["deny", "allow", "ask", "modify", "message", "return"],
  modify: { input: { replace: true, merge: true } },
};
interface Scenario {
  id: string;
  phase: "pending" | "accepted" | "timeout" | "failure";
  failurePolicy: "fail-open" | "fail-closed";
  effects: Effect[];
}
const scenarios: Scenario[] = JSON.parse(
  readFileSync(
    new URL("../../interop/interruption-scenarios.json", import.meta.url)
      .pathname,
    "utf8",
  ),
).scenarios;

test("canonical interruption scenarios through public Hooks and server over HTTP/stdio", async () => {
  const outcomes: unknown[][] = [];
  for (const kind of ["http", "stdio"] as const) {
    const rows: unknown[] = [];
    for (const scenario of scenarios) {
      const transport = await openInterruptionTransport(
        kind,
        capabilities,
        scenario.failurePolicy,
        scenario.phase === "timeout" ? 500 : 10000,
        scenario.phase === "pending" ? 2 : 1,
      );
      const independent = await openInterruptionTransport(kind, capabilities);
      try {
        const id = scenario.id;
        const pipeline = new DecisionPipeline(initial);
        const exchange = transport.start(
          id,
          initial.input,
          scenario.effects,
          scenario.phase === "failure" ? "not-json" : undefined,
        );
        const accepted = barrier(),
          execute = barrier();
        const run = pipeline.run(
          id,
          () => exchange,
          async () => {
            accepted.resolve();
            await execute.promise;
          },
        );
        await exchange.received;
        const request = transport.requests[0];
        assert.equal(request?.method, "hooks/intercept", id);
        if (request?.method !== "hooks/intercept")
          throw new Error("Missing interception");
        assert.equal(request.id, id);
        assert.equal(request.params.event.id, id);
        assert.equal(request.params.event.source, "urn:ahp:interruption");
        assert.equal(request.params.event.type, "tool.before");
        assert.equal(request.params.protocolVersion, "draft");
        assert.deepEqual(
          structuredClone(request.params.capabilities),
          capabilities,
        );
        if (scenario.phase === "pending") {
          const other = independent.start(id + "-unrelated", initial.input, []);
          await other.received;
          pipeline.interrupt();
          await run; // SDK abort settles without releasing the backend.
          const result = await exchange.response;
          assert.equal(result.interrupted, true, id);
          assert.equal(result.errors[0]?.code, "INTERRUPTED", id);
          assert.equal(result.errors[0]?.syntheticDenial, false, id);
          assert.deepEqual(result.response.result.effects, [], id);
          await other.release();
          assert.equal((await other.response).interrupted, false, id);
          assert.deepEqual((await other.response).errors, [], id);
          await exchange.release();
          assert.deepEqual(transport.routeRequests[1], [], id);
          assert.deepEqual(pipeline.state, initial, id);
          assert.deepEqual(
            pipeline.trace,
            [`dispatch:${id}`, "interrupt", "interrupted"],
            id,
          );
          assert.equal(pipeline.failures, 0, id);
        } else if (scenario.phase === "accepted") {
          await exchange.release();
          await accepted.promise;
          assert.deepEqual((await exchange.response).errors, [], id);
          pipeline.interrupt();
          execute.resolve();
          await run;
          // Explicit expected host outcomes from the unchanged canonical fixture;
          // no reference evaluator can validate or compose SDK results for us.
          const returned = scenario.effects.find(
            (effect) => effect.type === "return",
          );
          const changed = scenario.id === "accepted-compound";
          const input = changed ? { task: 2 } : initial.input;
          const expected: HostState = {
            ...initial,
            input,
            permission: scenario.id === "accepted-allow" ? "allow" : "native",
            candidate: returned
              ? { value: returned.value, supplier: id, input }
              : null,
            messages: changed ? ["accepted only"] : [],
          };
          assert.deepEqual(pipeline.state, expected, id);
          assert.deepEqual(pipeline.messages, expected.messages, id);
          assert.deepEqual(
            pipeline.trace,
            [
              `dispatch:${id}`,
              `accept:${id}`,
              ...expected.messages.map((m) => `message:${m}`),
              "interrupt",
              "interrupted",
            ],
            id,
          );
        } else {
          if (scenario.phase === "failure") await exchange.release();
          // Timeout comes from registration and SDK deadline, never local expire().
          await accepted.promise;
          execute.resolve();
          await run;
          if (scenario.phase === "timeout") await exchange.release();
          const result = await exchange.response;
          assert.equal(result.interrupted, false, id);
          assert.equal(result.errors.length, 1, id);
          assert.equal(
            result.errors[0]?.code,
            scenario.phase === "timeout"
              ? "DEADLINE_EXCEEDED"
              : "DELIVERY_FAILED",
            id,
          );
          assert.equal(
            result.errors[0]?.syntheticDenial,
            scenario.failurePolicy === "fail-closed",
            id,
          );
          assert.equal(
            result.response.result.effects.filter((e) => e.type === "deny")
              .length,
            scenario.failurePolicy === "fail-closed" ? 1 : 0,
            id,
          );
          assert.equal(pipeline.failures, 1, id);
          assert.deepEqual(
            pipeline.state,
            { ...initial, denied: scenario.failurePolicy === "fail-closed" },
            id,
          );
          assert.deepEqual(
            pipeline.trace,
            [
              `dispatch:${id}`,
              `reject:${id}`,
              scenario.phase === "timeout" ? "timeout" : "backend-failure",
              `failure:${scenario.failurePolicy}`,
              "policy",
              scenario.failurePolicy === "fail-open" ? "execute" : "blocked",
            ],
            id,
          );
        }
        assert.equal(
          pipeline.executions,
          (scenario.phase === "timeout" || scenario.phase === "failure") &&
            scenario.failurePolicy === "fail-open"
            ? 1
            : 0,
          id,
        );
        // Reuse the same Hooks instance. The SDK may replace an aborted stdio process.
        const freshId = id + "-fresh";
        const fresh = new DecisionPipeline(initial);
        const freshExchange = transport.start(freshId, initial.input, []);
        const freshRun = fresh.run(freshId, () => freshExchange);
        await freshExchange.received;
        await freshExchange.release();
        await freshRun;
        assert.equal(fresh.executions, 1, id);
        assert.equal(fresh.failures, 0, id);
        rows.push({
          id,
          state: pipeline.state,
          trace: pipeline.trace,
          messages: pipeline.messages,
          executions: pipeline.executions,
          failures: pipeline.failures,
        });
      } finally {
        await transport.dispose();
        await independent.dispose();
      }
    }
    outcomes.push(rows);
  }
  assert.deepEqual(outcomes[0], outcomes[1]);
});

test("host interruption before dispatch never starts a subscriber", async () => {
  const pipeline = new DecisionPipeline(initial);
  pipeline.interrupt();
  await pipeline.run("never", () => {
    throw new Error("unexpected dispatch");
  });
  assert.deepEqual(pipeline.trace, ["interrupt", "interrupted"]);
  assert.deepEqual(pipeline.state, initial);
  assert.equal(pipeline.executions, 0);
});

test("delivered public result queued for host acceptance is discarded on interruption", async () => {
  for (const kind of ["http", "stdio"] as const) {
    const transport = await openInterruptionTransport(kind, capabilities);
    try {
      const pipeline = new DecisionPipeline(initial);
      const exchange = transport.start("queued", initial.input, [
        {
          type: "modify",
          target: "input",
          operation: "merge",
          value: { task: 2 },
        },
        { type: "message", text: "unaccepted" },
        { type: "return", value: "unaccepted" },
      ]);
      await exchange.received;
      await exchange.release();
      const result = await exchange.response;
      assert.deepEqual(result.errors, []);
      // Real SDK result is resolved; host acceptance remains a queued continuation.
      const run = pipeline.run("queued", () => exchange);
      pipeline.interrupt();
      await run;
      assert.deepEqual(pipeline.state, initial);
      assert.deepEqual(pipeline.messages, []);
      assert.equal(pipeline.failures, 0);
      assert.equal(pipeline.executions, 0);
      assert.deepEqual(pipeline.trace, [
        "dispatch:queued",
        "interrupt",
        "interrupted",
      ]);
    } finally {
      await transport.dispose();
    }
  }
});

test("cancelled SDK-owned stdio process closes without a backend reply", async () => {
  const transport = await openInterruptionTransport("stdio", capabilities);
  const exchange = transport.start("dispose", initial.input, []);
  try {
    await exchange.received;
    exchange.cancel();
    assert.equal((await exchange.response).interrupted, true);
  } finally {
    await transport.dispose();
  }
  const replacement = await openInterruptionTransport("stdio", capabilities);
  try {
    const fresh = replacement.start("replacement", initial.input, []);
    await fresh.received;
    await fresh.release();
    assert.deepEqual((await fresh.response).errors, []);
  } finally {
    await replacement.dispose();
  }
});

test("synchronous interruption inside dispatch aborts the real boundary once", async () => {
  for (const kind of ["http", "stdio"] as const) {
    const transport = await openInterruptionTransport(kind, capabilities);
    try {
      const pipeline = new DecisionPipeline(initial);
      let cancellations = 0;
      await pipeline.run("synchronous", () => {
        pipeline.interrupt();
        const exchange = transport.start("synchronous", initial.input, []);
        return {
          response: exchange.response,
          cancel() {
            cancellations++;
            exchange.cancel();
            pipeline.interrupt();
          },
        };
      });
      assert.equal(cancellations, 1);
      assert.equal(pipeline.executions, 0);
      assert.equal(pipeline.failures, 0);
      assert.deepEqual(pipeline.state, initial);
      assert.deepEqual(pipeline.trace, [
        "dispatch:synchronous",
        "interrupt",
        "interrupted",
      ]);
    } finally {
      await transport.dispose();
    }
  }
});

test("native pre-execution interruption preserves accepted SDK effects", async () => {
  for (const kind of ["http", "stdio"] as const) {
    for (const reentrant of [true, false]) {
      const transport = await openInterruptionTransport(kind, capabilities);
      try {
        const pipeline = new DecisionPipeline(initial),
          entered = barrier(),
          release = barrier();
        const exchange = transport.start("accepted", initial.input, [
          {
            type: "modify",
            target: "input",
            operation: "merge",
            value: { task: 2 },
          },
          { type: "return", value: "accepted candidate" },
          { type: "message", text: "accepted message" },
        ]);
        const run = pipeline.run(
          "accepted",
          () => exchange,
          async () => {
            entered.resolve();
            if (reentrant) pipeline.interrupt();
            else await release.promise;
          },
        );
        await exchange.received;
        await exchange.release();
        await entered.promise;
        if (!reentrant) {
          pipeline.interrupt();
          release.resolve();
        }
        await run;
        assert.deepEqual((await exchange.response).errors, []);
        assert.equal(pipeline.interrupted, true);
        assert.equal(pipeline.executions, 0);
        assert.equal(pipeline.failures, 0);
        assert.equal(pipeline.state.input.task, 2);
        assert.equal(pipeline.state.candidate?.value, "accepted candidate");
        assert.deepEqual(pipeline.messages, ["accepted message"]);
        assert.equal(pipeline.trace.at(-1), "interrupted");
        assert.equal(
          pipeline.trace.some((entry) => entry.startsWith("candidate:")),
          false,
        );
      } finally {
        await transport.dispose();
      }
    }
  }
});

test("one Hooks boundary composes ordered routes and invalidates earlier grants/candidates", async () => {
  for (const kind of ["http", "stdio"] as const) {
    const transport = await openInterruptionTransport(
      kind,
      capabilities,
      "fail-open",
      10000,
      2,
    );
    try {
      const id = "ordered-composition";
      const pipeline = new DecisionPipeline(initial);
      const exchange = transport.start(
        id,
        initial.input,
        [
          {
            type: "modify",
            target: "input",
            operation: "merge",
            value: { task: 2 },
          },
          { type: "allow" },
          { type: "return", value: "stale candidate" },
          { type: "message", text: "first route" },
        ],
        undefined,
        [
          {
            hold: true,
            effects: [
              {
                type: "modify",
                target: "input",
                operation: "merge",
                value: { task: 3 },
              },
              { type: "message", text: "second route" },
            ],
          },
        ],
      );
      const run = pipeline.run(id, () => exchange);
      await exchange.received;
      await exchange.release();
      await exchange.routes[1]!.received;
      // The host has accepted nothing: this is still the same pending boundary.
      assert.deepEqual(pipeline.state, initial);
      const second = transport.routeRequests[1]![0];
      if (
        second?.method !== "hooks/intercept" ||
        second.params.event.type !== "tool.before"
      )
        throw new Error("Expected second tool interception");
      assert.equal(second.id, id);
      assert.equal(second.params.event.id, id);
      assert.deepEqual(structuredClone(second.params.event.tool.input), {
        task: 2,
      });
      assert.equal(second.params.state?.permission, "allow");
      assert.deepEqual(structuredClone(second.params.state?.candidate), {
        value: "stale candidate",
      });
      await exchange.routes[1]!.release();
      await run;
      const result = await exchange.response;
      assert.deepEqual(result.errors, []);
      assert.equal(
        result.response.result.effects.some(
          (effect) => effect.type === "allow" || effect.type === "return",
        ),
        false,
      );
      assert.deepEqual(structuredClone(result.event.tool.input), { task: 3 });
      assert.deepEqual(pipeline.state, {
        ...initial,
        input: { task: 3 },
        messages: ["first route", "second route"],
      });
      assert.equal(pipeline.executions, 1);
      assert.deepEqual(pipeline.trace, [
        `dispatch:${id}`,
        `accept:${id}`,
        "message:first route",
        "message:second route",
        "policy",
        "execute",
      ]);
    } finally {
      await transport.dispose();
    }
  }
});

test("interruption of an ordered SDK route prevents later routes and late compound effects", async () => {
  for (const kind of ["http", "stdio"] as const) {
    for (const failurePolicy of ["fail-open", "fail-closed"] as const) {
      const transport = await openInterruptionTransport(
        kind,
        capabilities,
        failurePolicy,
        10000,
        3,
      );
      try {
        const id = "ordered-interruption";
        const pipeline = new DecisionPipeline(initial);
        const exchange = transport.start(
          id,
          initial.input,
          [
            {
              type: "modify",
              target: "input",
              operation: "merge",
              value: { task: 2 },
            },
            { type: "allow" },
            { type: "return", value: "earlier candidate" },
            { type: "message", text: "earlier SDK message" },
          ],
          undefined,
          [
            {
              hold: true,
              effects: [
                {
                  type: "modify",
                  target: "input",
                  operation: "merge",
                  value: { task: 3 },
                },
                { type: "return", value: "late candidate" },
                { type: "message", text: "late message" },
              ],
            },
            { effects: [{ type: "message", text: "never" }] },
          ],
        );
        const run = pipeline.run(id, () => exchange);
        await exchange.received;
        await exchange.release();
        await exchange.routes[1]!.received;
        pipeline.interrupt();
        await run;
        const result = await exchange.response;
        assert.equal(result.interrupted, true);
        assert.equal(result.errors.length, 1);
        assert.equal(result.errors[0]?.backendId, "test.interruption1");
        assert.equal(result.errors[0]?.code, "INTERRUPTED");
        assert.equal(result.errors[0]?.syntheticDenial, false);
        assert.deepEqual(structuredClone(result.event.tool.input), { task: 2 });
        assert.equal(
          result.response.result.effects.some(
            (effect) =>
              effect.type === "allow" ||
              effect.type === "return" ||
              effect.type === "deny",
          ),
          false,
        );
        assert.deepEqual(
          result.response.result.effects
            .filter((effect) => effect.type === "message")
            .map((effect) => effect.text),
          ["earlier SDK message"],
        );
        await exchange.routes[1]!.release();
        assert.deepEqual(transport.routeRequests[2], []);
        // SDK accepted route one internally, but host never accepted the boundary.
        assert.deepEqual(pipeline.state, initial);
        assert.deepEqual(pipeline.messages, []);
        assert.equal(pipeline.executions, 0);
        assert.equal(pipeline.failures, 0);
      } finally {
        await transport.dispose();
      }
    }
  }
});
