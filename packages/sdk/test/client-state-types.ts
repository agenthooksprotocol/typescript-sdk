import type {
  BoundaryResult,
  BoundaryState,
  EventCapabilities,
  EventGrant,
} from "agenthooksprotocol/client";

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

// Origin determines schema-owned candidate values without consumer casts.
declare const messages: BoundaryResult<'model.request.before'>;
if (messages.state.candidate !== null) {
  const role: string = messages.state.candidate.value[0]!.role;
  const kind: string = messages.state.candidate.value[0]!.parts[0]!.kind;
  void [role, kind];
  // @ts-expect-error Canonical messages are not a text part list.
  const notText: string = messages.state.candidate.value[0]!.text;
  void notText;
}
declare const text: BoundaryResult<'context.compact.before'>;
if (text.state.candidate !== null) {
  const kind: string = text.state.candidate.value[0]!.kind;
  void kind;
  // @ts-expect-error Text parts are not whole messages.
  const notMessages: string = text.state.candidate.value[0]!.parts;
  void notMessages;
}
declare const elicit: BoundaryResult<'user.elicitation.request'>;
if (elicit.state.candidate !== null) {
  const action: string = elicit.state.candidate.value.action;
  void action;
  // @ts-expect-error The complete action envelope is not merely a form answer.
  const answer: string = elicit.state.candidate.value.content;
  void answer;
}
const eventType: 'model.request.before' = messages.settledEvent.type;
const eventMessages = messages.settledEvent.items;
if (messages.state.injections) {
  const delivery: string = messages.state.injections[0]!.deliverAt;
  const target: 'context' = messages.state.injections[0]!.target;
  const role: string = messages.state.injections[0]!.value[0]!.role;
  void [delivery, target, role];
}
void [eventType, eventMessages];

for (const response of messages.acceptedResponses) {
  for (const effect of response.result.effects ?? []) {
    if (effect.type === 'return') {
      const role: string = effect.value[0]!.role;
      void role;
      // @ts-expect-error Model return effects contain messages, not tool scalars.
      const scalar: string = effect.value;
      void scalar;
    }
  }
}
