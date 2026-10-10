// Consumer compile regression through public declarations, not source imports.
import {
  Hooks,
  type BoundaryInput,
  type HarnessEvent,
} from "agenthooksprotocol/client";

declare const hooks: Hooks;
const body = new ReadableStream<Uint8Array>();
for (const trigger of ["auto", "manual", "hook"] as const) {
  const input: BoundaryInput<"context.compact.before"> = {
    trigger,
    items: [],
    instructions: [{
      id: "instructions", kind: "text", mediaType: "text/plain",
      selection: "body", text: "Summarize the conversation",
    }],
    tokenCounts: { before: 100 },
  };
  void hooks.dispatch("context.compact.before", input);
  void hooks.dispatch("context.compact.before", input);
}
const minimal: BoundaryInput<"context.compact.before"> = {
  trigger: "manual",
  items: [],
};
void minimal;
declare const event: HarnessEvent<"context.compact.before">;
const trigger: string = event.trigger;
void [trigger, event.instructions?.[0]?.mediaType];
// @ts-expect-error Canonical trigger is required.
const missingTrigger: BoundaryInput<"context.compact.before"> = { items: [] };
// @ts-expect-error Canonical items are required.
const missingItems: BoundaryInput<"context.compact.before"> = {
  trigger: "auto",
};
const invalidTrigger: BoundaryInput<"context.compact.before"> = {
  // @ts-expect-error Trigger must be a string.
  trigger: 1,
  items: [],
};
const invalidInstructions: BoundaryInput<"context.compact.before"> = {
  trigger: "hook",
  items: [],
  // @ts-expect-error Instructions are inline text parts, not a bare stream.
  instructions: body,
};
const missingContentFields: BoundaryInput<"context.compact.before"> = {
  trigger: "manual",
  items: [],
  // @ts-expect-error Metadata required by the content item is not optional.
  instructions: [{ body }],
};
void [
  missingTrigger,
  missingItems,
  invalidTrigger,
  invalidInstructions,
  missingContentFields,
];

// Compaction items are role-bearing messages; only binary parts own bytes.
import { Attachment } from "agenthooksprotocol/client";
declare const ownedHooks: import("agenthooksprotocol/client").Hooks;
const owned = Attachment.bytes(new Uint8Array([1, 2]));
const deferred = Attachment.lazy(async (signal) => {
  signal.throwIfAborted();
  return new Uint8Array([3]);
}, async () => {});
void ownedHooks.contextCompactBefore({
  trigger: "manual", items: [{ id: "message", role: "user", parts: [
    { id: "owned", kind: "attachment", mediaType: "application/octet-stream", selection: "body", body: owned },
  ] }],
}).then(async result => {
  const bytes: Uint8Array | undefined = await result.content?.read("owned");
  void bytes;
  await result.content?.close();
});
void ownedHooks.contextCompactBefore({
  trigger: "manual", items: [{ id: "message", role: "user", parts: [
    { id: "deferred", kind: "attachment", mediaType: "application/octet-stream", selection: "body", body: deferred },
  ] }],
});
