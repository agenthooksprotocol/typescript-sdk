// Consumer-only compile check: resolve declarations through the public package export.
import {
  Hooks,
  type BoundaryInput,
  type BoundaryResult,
  type EventType,
  type HarnessEvent,
  type HooksOptions,
  type StaticCapabilityManifest,
} from "agenthooksprotocol/client";

const options: HooksOptions = {
  source: "urn:test:harness",
  capabilities: {
    "tool.before": {
      modes: ["intercept", "observe"],
      capabilities: { effects: ["deny", "modify"] },
    },
    "user.message.inbound": { modes: ["observe"] },
    "model.request.before": { modes: ["observe"] },
    "session.start": { modes: ["observe"] },
  },
};
const hooks = new Hooks(
  {
    protocolVersion: "draft",
    hooks: [
      {
        id: "test.types",
        transport: { type: "http", url: "https://backend.test/hooks" },
        subscriptions: [
          { mode: "observe", events: ["*"], content: { default: "metadata" } },
        ],
      },
    ],
  },
  options,
);
const minimalTool: BoundaryInput<"tool.before"> = {
  call: { id: "call-1" },
  path: "native",
  tool: { name: "read_file", origin: "native", input: { path: "README.md" } },
};
const pending: Promise<BoundaryResult<"tool.before">> = hooks.dispatch(
  "tool.before",
  minimalTool,
);
void pending;

function inspectTool(result: BoundaryResult<"tool.before">): void {
  const event: HarnessEvent<"tool.before"> = result.event;
  const type: "tool.before" = event.type;
  const id: string = event.id;
  const source: string = event.source;
  const time: string = event.time;
  const name: string = event.tool.name;
  void [type, id, source, time, name];
  // @ts-expect-error A tool.before result does not become a session.start result.
  const wrong: BoundaryResult<"session.start"> = result;
  void wrong;
}
void inspectTool;

const stream = new ReadableStream<Uint8Array>();
// The harness supplies raw bytes; delivery selection and the wire ref are SDK-owned.
const rawMessage: BoundaryInput<"user.message.inbound"> = {
  message: {
    channel: "chat",
    sender: "user",
    text: [
      {
        id: "message-1",
        kind: "message",
        mediaType: "text/plain",
        body: stream,
      },
    ],
  },
};
void hooks.dispatch("user.message.inbound", rawMessage);
void hooks.dispatch("model.request.before", {
  model: { id: "model", provider: "provider" },
  attempt: { id: "attempt", number: 1 },
  params: {},
  items: [
    {
      id: "prompt-1",
      kind: "message",
      mediaType: "text/plain",
      role: "user",
      body: stream,
    },
  ],
});
void hooks.dispatch("session.start", {
  session: { id: "session-1" },
  harness: { name: "consumer", version: "1" },
  permissionMode: "default",
  trigger: "startup",
  items: [],
});
void hooks.dispatch(
  "tool.before",
  { ...minimalTool, id: "occurrence", time: "2026-01-01T00:00:00Z" },
  {
    signal: new AbortController().signal,
    initialState: { permission: "none", candidate: null },
    capabilities: { effects: ["deny"] },
  },
);

void hooks.dispatch("tool.before", minimalTool, {
  // @ts-expect-error The boundary option is initialState, not the wire state field.
  state: { permission: "none", candidate: null },
});

declare const manifest: StaticCapabilityManifest;
const staticOptions: HooksOptions = {
  source: "urn:test:harness",
  capabilities: manifest,
};
void staticOptions;
const knownEvent: EventType = "file.changed";
void knownEvent;

// @ts-expect-error Canonical event names are a closed public method catalogue.
const unknownEvent: EventType = "tool.typo";
// @ts-expect-error tool.before needs tool, path, and call.
void hooks.dispatch("tool.before", {});
void hooks.dispatch("tool.before", {
  ...minimalTool,
  // @ts-expect-error Tool input is not a substitute for the required tool name.
  tool: { input: {}, origin: "native" },
});
void hooks.dispatch("tool.before", {
  ...minimalTool,
  // @ts-expect-error Envelope source is generated from HooksOptions.
  source: "urn:forged:source",
});
// @ts-expect-error The method owns the canonical type discriminator.
void hooks.dispatch("tool.before", { ...minimalTool, type: "tool.after" });
void hooks.dispatch("user.message.inbound", {
  message: {
    channel: "chat",
    sender: "user",
    text: [
      {
        id: "bad",
        kind: "message",
        mediaType: "text/plain",
        // @ts-expect-error Body bytes must be a byte stream or a canonical content reference, not a string.
        body: "not a stream",
      },
    ],
  },
});
void hooks.dispatch("user.message.inbound", {
  message: {
    channel: "chat",
    sender: "user",
    text: [
      {
        id: "bad",
        kind: "message",
        mediaType: "text/plain",
        // @ts-expect-error A text stream is not a byte stream.
        body: new ReadableStream<string>(),
      },
    ],
  },
});
// @ts-expect-error Boundary cancellation requires an AbortSignal.
void hooks.dispatch("tool.before", minimalTool, { signal: "cancel" });
void unknownEvent;

// Generated ergonomic host inputs are distinct from canonical dispatch inputs.
import {
  Permission,
  state,
  effects,
  ContentSource,
  type EventInput,
  type ToolBeforeInput,
  type DeliveryDiagnosticCode,
  type DeliveryAuthProvider,
} from "agenthooksprotocol/client";
const generatedFacts: ToolBeforeInput = {
  callId: "call",
  name: "read_file",
  input: { path: "README.md" },
  path: "native",
  origin: "native",
};
void hooks.toolBefore(generatedFacts, {
  initialState: state.initial(Permission.Allow, {
    candidate: state.candidate(null),
  }),
});
const lazyFacts: EventInput<"tool.before"> = {
  ...generatedFacts,
  items: [
    {
      id: "body",
      kind: "text",
      mediaType: "text/plain",
      body: new ContentSource(new ReadableStream<Uint8Array>()),
    },
  ],
};
void hooks.toolBefore(lazyFacts);
// @ts-expect-error Named methods require generated flattened facts, not canonical wrappers.
void hooks.toolBefore(minimalTool);
// @ts-expect-error Origin and path are distinct required host facts.
void hooks.toolBefore({
  callId: "call",
  name: "read_file",
  input: {},
  path: "native",
});
// @ts-expect-error A replacement payload is required.
void effects.modify_input.replace();
const credentialProvider: DeliveryAuthProvider = {
  credential(context) {
    return context.authentication
      ? { type: "bearer", token: "host-selected", attempt: { version: 1 } }
      : undefined;
  },
  challenge(context) {
    void [
      context.backendId,
      context.purpose,
      context.response,
      context.credential?.attempt,
    ];
  },
};
void credentialProvider;
function inspectErgonomicResult(result: BoundaryResult<"tool.before">) {
  const accepted: unknown = result.input;
  const permission: "none" | "allow" | "ask" | "deny" = result.permission;
  const cause: DeliveryDiagnosticCode = result.diagnostics[0]!.code;
  void [accepted, permission, cause];
  // @ts-expect-error Hook-modified JSON is not application-validated input.
  const validated: { path: string } = result.input;
  void validated;
}
void inspectErgonomicResult;
