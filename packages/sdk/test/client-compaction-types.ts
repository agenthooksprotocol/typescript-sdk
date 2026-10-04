// Consumer compile regression through public declarations, not source imports.
import {
  Hooks,
  type BoundaryInput,
  type HarnessEvent,
} from "@agenthooksprotocol/sdk/client";

declare const hooks: Hooks;
const body = new ReadableStream<Uint8Array>();
for (const trigger of ["auto", "manual", "hook"] as const) {
  const input: BoundaryInput<"context.compact.before"> = {
    trigger,
    items: [],
    instructions: {
      id: "instructions",
      kind: "text",
      mediaType: "text/plain",
      body,
    },
    tokenCounts: { before: 100 },
  };
  void hooks.contextCompactBefore(input);
  void hooks.dispatch("context.compact.before", input);
}
const minimal: BoundaryInput<"context.compact.before"> = {
  trigger: "manual",
  items: [],
};
void minimal;
declare const event: HarnessEvent<"context.compact.before">;
const trigger: string = event.trigger;
void [trigger, event.instructions?.mediaType];
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
  // @ts-expect-error Instructions are a content item, not a bare stream.
  instructions: body,
};
const missingContentFields: BoundaryInput<"context.compact.before"> = {
  trigger: "manual",
  items: [],
  // @ts-expect-error Metadata required by the content item is not optional.
  instructions: { body },
};
void [
  missingTrigger,
  missingItems,
  invalidTrigger,
  invalidInstructions,
  missingContentFields,
];
