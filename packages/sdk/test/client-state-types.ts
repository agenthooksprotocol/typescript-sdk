import type {
  BoundaryResult,
  BoundaryState,
  EventCapabilities,
  EventGrant,
} from "@agenthooksprotocol/sdk/client";

const observe: EventGrant = { modes: ["observe"] };
const both: EventGrant = {
  modes: ["intercept", "observe"],
  capabilities: { effects: ["deny"] },
};
const grants: EventCapabilities = {
  "tool.after": observe,
  "tool.before": both,
  "session.start": { effects: [] },
};
void grants;
const invalid: EventGrant = {
  // @ts-expect-error Delivery modes are explicit canonical modes.
  modes: ["automatic"],
};
void invalid;
declare const result: BoundaryResult<"tool.before">;
const state: BoundaryState = result.state;
// Canonical generated enums preserve forward-compatible strings.
const permission: string = state.permission;
void permission;
// @ts-expect-error The returned state property cannot be replaced.
result.state = { permission: "none", candidate: null };
// @ts-expect-error Canonical state properties are readonly.
state.permission = "allow";
// @ts-expect-error Candidate decisions are readonly.
state.candidate = null;
if (state.candidate) {
  // @ts-expect-error Candidate values are detached readonly data.
  state.candidate.value = "replacement";
}
if (state.instructions) {
  // @ts-expect-error Continuation instructions cannot be mutated.
  state.instructions.push("replacement");
}
