import test from "node:test";
import assert from "node:assert/strict";
import { stageBoundary } from "../dist/src/draft-runtime.js";

const state = {
  input: { task: 1 }, candidate: null, permission: "native",
  approval: "pending", denied: false, messages: [], values: { output: "before" },
};
const effect = { type: "modify", target: "input", operation: "replace", value: { task: 2 } };

test("synthetic boundaries grant modifications with canonical operation booleans", () => {
  const result = stageBoundary(state, [effect], {
    effects: ["modify"], modify: { input: { replace: true } },
  }, "hook");
  assert.equal(result.input.task, 2);
  assert.equal(state.input.task, 1);
});

test("legacy modify operation lists do not grant capability authority", () => {
  for (const output of [{ operations: ["replace"] }, { replace: false, operations: ["replace"] }]) {
    assert.throws(() => stageBoundary(state, [effect], {
      effects: ["modify"], modify: { input: output },
    }, "hook"), /Unsupported target or operation/);
  }
});
