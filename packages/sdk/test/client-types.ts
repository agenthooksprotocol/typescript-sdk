// Consumer-only compile check: resolve declarations through the public package export.
import {
  Hooks,
  type BoundaryInput,
  type BoundaryResult,
  type EventType,
  type HarnessEvent,
  type HooksOptions,
  type StaticCapabilityManifest,
} from "@agenthooksprotocol/sdk/client";

const options: HooksOptions = {
  source: "urn:test:harness",
  capabilities: { "tool.before": { effects: ["deny", "modify"] } },
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
const pending: Promise<BoundaryResult<"tool.before">> =
  hooks.toolBefore(minimalTool);
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
void hooks.userMessageInbound(rawMessage);
void hooks.modelRequestBefore({
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
void hooks.sessionStart({
  session: { id: "session-1" },
  harness: { name: "consumer", version: "1" },
  permissionMode: "default",
  trigger: "startup",
  items: [],
});
void hooks.toolBefore(
  { ...minimalTool, id: "occurrence", time: "2026-01-01T00:00:00Z" },
  {
    signal: new AbortController().signal,
    initialState: { permission: "none", candidate: null },
    capabilities: { effects: ["deny"] },
  },
);

void hooks.toolBefore(minimalTool, {
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
void hooks.toolBefore({});
void hooks.toolBefore({
  ...minimalTool,
  // @ts-expect-error Tool input is not a substitute for the required tool name.
  tool: { input: {}, origin: "native" },
});
// @ts-expect-error Envelope source is generated from HooksOptions.
void hooks.toolBefore({ ...minimalTool, source: "urn:forged:source" });
// @ts-expect-error The method owns the canonical type discriminator.
void hooks.toolBefore({ ...minimalTool, type: "tool.after" });
void hooks.userMessageInbound({
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
void hooks.userMessageInbound({
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
void hooks.toolBefore(minimalTool, { signal: "cancel" });
void unknownEvent;
