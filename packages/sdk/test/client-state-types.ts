import type {
  BoundaryResult,
  BoundaryState,
  HostCapabilities,
} from "agenthooksprotocol/client";

const observe: NonNullable<HostCapabilities["toolBefore"]> = { observe: true };
const both: NonNullable<HostCapabilities["toolBefore"]> = { intercept: { deny: true }, observe: true };
const grants: HostCapabilities = {
  toolAfter: { observe: true },
  toolBefore: both,
  sessionStart: { intercept: { message: true } },
};
void grants;
const invalid: HostCapabilities = {
  // @ts-expect-error Observation-only events do not admit interception.
  sessionEnd: { intercept: { deny: true } },
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
const eventType: 'model.request.before' = messages.event.type;
const eventMessages = messages.event.items;
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

for (const effect of messages.effects) {
  // @ts-expect-error Accepted returns are execution facts in state.candidate, not residual effects.
  if (effect.type === 'return') void effect;
  // @ts-expect-error Accepted modifications are execution facts in event, not residual effects.
  if (effect.type === 'modify') void effect;
}

// Removed declaration APIs must not return through public exports.
// @ts-expect-error Legacy builder class is not public.
import { CapabilityBuilder } from "agenthooksprotocol/client";
// @ts-expect-error Legacy capability constructor is not public.
import { capabilities } from "agenthooksprotocol/client";
import type { StaticCapabilityManifest, HooksOptions } from "agenthooksprotocol/client";
declare const wireManifest: StaticCapabilityManifest;
const invalidManifest: HooksOptions = {
  source: "urn:test:manifest", harness: { name: 'test', version: '1' },
  // @ts-expect-error A canonical discovery manifest is not a typed host declaration.
  capabilities: wireManifest,
};
void invalidManifest;
// @ts-expect-error Legacy event grants are not public.
import type { EventGrant } from "agenthooksprotocol/client";
// @ts-expect-error Legacy event capability maps are not public.
import type { EventCapabilities } from "agenthooksprotocol/client";
// @ts-expect-error Draft generated exports must not retain the builder.
import { CapabilityBuilder as DraftBuilder } from "agenthooksprotocol/draft";
// @ts-expect-error Server exports must not retain the generic result type.
import type { InterceptResult } from "agenthooksprotocol/server";
// @ts-expect-error Server exports must not retain the generic handler type.
import type { Handler } from "agenthooksprotocol/server";
const badEvent: HostCapabilities = {
  // @ts-expect-error Known catalogue entries use camelCase fields, not wire keys.
  "tool.before": { intercept: { deny: true } },
};
const badControl: HostCapabilities = {
  // @ts-expect-error Known tool controls do not include summary modifications.
  toolBefore: { intercept: { modifySummary: "replace" } },
};
const badModification: HostCapabilities = {
  // @ts-expect-error Modification operations are catalogue literals.
  toolBefore: { intercept: { modifyInput: "append" } },
};
const badBoolean: HostCapabilities = {
  // @ts-expect-error Presence grants are literal true, not arbitrary booleans.
  toolBefore: { intercept: { deny: false } },
};
void [badEvent, badControl, badModification, badBoolean];
