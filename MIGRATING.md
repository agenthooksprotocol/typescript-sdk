# Migrating

## 0.4 → 0.5

0.5.0 removes the draft compatibility surfaces and replaces them with typed,
event-specific APIs (#24). There is no compatibility layer: code that uses the
removed names does not compile. Protocol wire messages do not change.

Snippets assume that `config` (a registration), `hooks` (a `Hooks` instance),
`stream` (a `ReadableStream<Uint8Array>`), and `manifest` (a capability manifest)
already exist.

### Summary

| 0.4 API                                                                                                                                                                                       | 0.5 replacement                                                                                                                                          |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ToolBeforeRunner` (root)                                                                                                                                                                     | `Hooks` from `agenthooksprotocol/client` with a stdio backend in the registration ([below](#toolbeforerunner))                                           |
| `runCompaction`, `compactionCapabilities`, `CompactionHook`, `CompactionObserver`, `CompactionEffect` (root)                                                                                  | `hooks.contextCompactBefore(...)` and `hooks.contextCompactAfter(...)` with `contextCompactBefore` / `contextCompactAfter` host capabilities             |
| `asOperationalError` (root)                                                                                                                                                                   | Removed, no replacement. Construct `new HookOperationalError(code, message, { cause })` yourself ([below](#asoperationalerror))                          |
| `applyElicitationEffects` (root)                                                                                                                                                              | Removed, no replacement. `Hooks` settles `user.elicitation.request` boundaries; read the result from `result.state` and `result.acceptedResponses`       |
| Root protocol models: `ToolBeforeEvent`, `InterceptRequest`, `InterceptResponse`, `InterceptResult`, `DenyEffect`, `SessionContext`, `ToolContext`, `NativeContext`, `ToolKind`, `TOOL_KINDS` | Generated models from `agenthooksprotocol/draft` (for example `ToolBeforeEvent`, `InterceptRequest`, `InterceptResponse`, `DenyEffect`, `Effect`)        |
| Root `PROTOCOL_VERSION`, `INTERCEPT_METHOD`                                                                                                                                                   | `PROTOCOL_VERSION` from `agenthooksprotocol/draft`; use the literal `"hooks/intercept"`                                                                  |
| Root runner types: `HookBackend`, `ToolBeforeInput`, `ToolBeforeOutcome`, `HookFailure`, `FailurePolicy`, `Lifecycle`, `IdKind`, `IdGenerator`                                                | `Backend` / `Registration` from `agenthooksprotocol/draft`, `ToolBeforeInput` / `BoundaryResult` / `DeliveryDiagnostic` from `agenthooksprotocol/client` |
| Root `parseInterceptRequest(line)`, `parseInterceptResponse(line)`                                                                                                                            | `parseInterceptRequest`, `parseInterceptResponse`, `validateInterceptRequest`, `validateInterceptResponse` from `agenthooksprotocol/draft`               |
| `capabilities.intercept()...`, `capabilities.observe()`, `CapabilityBuilder`                                                                                                                  | Plain `HostCapabilities` objects; `capabilityCount(n)` for flow counts; `hostCapabilitiesToWire` for canonical grants                                    |
| `EventCapabilities`, `EventGrant`, `CapabilityDeclaration`, `CapabilityModifyOperations`                                                                                                      | `HostCapabilities` (camel-keyed, for example `toolBefore`), with `CapabilityFlow`, `CapabilityInjection`, `CapabilityElicitation`, `CapabilityCount`     |
| `CapabilityObservation` (`{ modes: ["observe"] }`)                                                                                                                                            | `CapabilityObservation` (`{ observe: true }`)                                                                                                            |
| `HooksOptions.capabilities` as a `StaticCapabilityManifest`                                                                                                                                   | `HooksOptions.capabilities: HostCapabilities` plus `HooksOptions.manifestMetadata` for non-event advertisements                                          |
| `contentSlots[event].slot(index, source)`                                                                                                                                                     | Write `ContentSourceBinding` values directly: `{ path: ["items", 0], source: attachment }`                                                               |
| `ContentSource`                                                                                                                                                                               | `Attachment` (`bytes`, `lazy`, `stream`)                                                                                                                 |
| `Attachment.fromStream(stream)`                                                                                                                                                               | `Attachment.stream(stream)`                                                                                                                              |
| Raw `ReadableStream` content bodies, `StreamContentItem`                                                                                                                                      | Wrap the stream: `body: Attachment.stream(stream)`                                                                                                       |
| `DeliveryError`                                                                                                                                                                               | `DeliveryDiagnostic` (`code` is now a `DeliveryDiagnosticCode`)                                                                                          |
| `result.errors`, `result.observations`                                                                                                                                                        | `result.diagnostics`; filter by `phase` (`"observation"` for observation failures)                                                                       |
| `result.permission`                                                                                                                                                                           | `result.state.permission`                                                                                                                                |
| `result.input`                                                                                                                                                                                | `result.event.tool.input`                                                                                                                                |
| `result.settledEvent`                                                                                                                                                                         | `result.event` (now the decoded canonical event)                                                                                                         |
| `result.response`                                                                                                                                                                             | `result.effects` for residual actions, `result.acceptedResponses` for complete receiver envelopes                                                        |
| `AuthCredential`                                                                                                                                                                              | `Credential`                                                                                                                                             |
| `AuthOverrides`                                                                                                                                                                               | `AuthOptions`                                                                                                                                            |
| `HooksOptions.auth` typed `AuthProvider \| DeliveryAuthProvider`                                                                                                                              | `DeliveryAuthProvider`. `auth()` still works; custom providers must implement `credential` and `challenge`                                               |
| Server `Message`, `Handler`, `InterceptResult`, `CapabilitiesResult`, one raw callback                                                                                                        | `ServerHandlers` with `intercept`, `observe`, and `capabilities` maps; `ServerReply`, `InterceptContext`, `ObservationContext`                           |
| `serveStdio((request) => hooks.handle(request, handler))`                                                                                                                                     | `serveStdio(handlers)`                                                                                                                                   |
| Server `effects` (`effects.deny`, `effects.modify_input_effect`, ...)                                                                                                                         | Server `effect` (`effect.deny`, `effect.replaceInput`, `effect.mergeInput`, `effect.stop`, ...)                                                          |
| No equivalent                                                                                                                                                                                 | New: `hooks.subscribes(eventType)` reports static subscription interest                                                                                  |

### `ToolBeforeRunner`

The root runner supported only the deny/no-effect `tool.before` slice. Describe
the backend in a registration and use `Hooks`.

Before:

```ts
import { ToolBeforeRunner } from "agenthooksprotocol";

const runner = new ToolBeforeRunner();
const unregister = runner.register({
  command: "/path/to/hook-backend",
  args: [],
  timeoutMs: 2_000,
  failurePolicy: "fail-closed",
  lifecycle: "persistent",
});
const outcome = await runner.intercept({
  source: "https://example.com/agent",
  session: {},
  tool: {
    name: "write_file",
    kind: "file_write",
    input: { path: "README.md", content: "example" },
  },
});
if (outcome.decision === "deny") console.error(outcome.denial?.reason);
unregister();
```

After:

```ts
import { Hooks, Permission } from "agenthooksprotocol/client";

const registration = {
  protocolVersion: "draft",
  hooks: [
    {
      id: "com.example.policy",
      transport: {
        type: "stdio",
        command: "/path/to/hook-backend",
        args: [],
        lifecycle: "persistent",
      },
      subscriptions: [
        {
          mode: "intercept",
          events: ["tool.before"],
          timeoutMs: 2000,
          failurePolicy: "fail-closed",
        },
      ],
    },
  ],
};
const runner = new Hooks(registration, {
  source: "https://example.com/agent",
  capabilities: { toolBefore: { intercept: { deny: true } } },
});
try {
  const outcome = await runner.toolBefore({
    callId: "call-1",
    name: "write_file",
    path: "native",
    origin: "native",
    input: { path: "README.md", content: "example" },
  });
  if (outcome.interrupted || outcome.state.permission === Permission.Deny) {
    const denial = outcome.effects.find((e) => e.type === "deny");
    console.error(denial?.reason);
  }
} finally {
  await runner.close();
}
```

### Host capabilities

Builders and string-keyed grant records are replaced by plain, camel-keyed
declarations. TypeScript rejects controls that an event does not support.
Observation is never implied: `capability.intercept()` used to advertise both
modes, so add `observe: true` to keep observation.

Before:

```ts
import {
  capabilities as capability,
  events,
  type EventCapabilities,
} from "agenthooksprotocol/client";

const capabilities: EventCapabilities = {
  [events.toolBefore]: capability
    .intercept()
    .deny()
    .modifyInput({ replace: true }),
  "tool.after": { modes: ["observe"] },
};
```

After:

```ts
import {
  Hooks,
  capabilityCount,
  type HostCapabilities,
} from "agenthooksprotocol/client";
import { hostCapabilitiesToWire } from "agenthooksprotocol/draft";

const capabilities = {
  toolBefore: {
    intercept: { deny: true, modifyInput: "replace" },
    observe: true,
  },
  toolAfter: { observe: true },
  turnFinishBefore: {
    intercept: {
      flow: {
        operations: ["stop", "continue"],
        remainingContinuations: capabilityCount(3),
        continuationCount: capabilityCount(0),
      },
    },
  },
} satisfies HostCapabilities;

// Canonical per-event grants, if you need them on the wire.
const wire = hostCapabilitiesToWire(capabilities);

const hooks = new Hooks(config, {
  source: "urn:example:agent",
  capabilities,
  // Non-event advertisements that used to live in a static manifest.
  manifestMetadata: { transports: ["stdio"] },
});
```

`manifestMetadata` cannot contain `events`; event grants always come from
`capabilities`.

### Boundary results

Before:

```ts
const result = await hooks.toolBefore(input);
const denied = result.permission === Permission.Deny;
const args = result.input;
const effects = result.response.result.effects;
const observationErrors = await result.observations;
```

After:

```ts
import { Permission, type DeliveryDiagnostic } from "agenthooksprotocol/client";

const result = await hooks.toolBefore({
  callId: "call-1",
  name: "read",
  path: "native",
  origin: "native",
  input: { path: "README.md" },
});
const denied = result.state.permission === Permission.Deny;
const args = result.event.tool.input;
// Residual actions to enact. Edits are already in result.event and returns in
// result.state.candidate; do not replay them.
const residual = result.effects;
// Complete receiver envelopes, in acceptance order.
const accepted = result.acceptedResponses;
const observationFailures: DeliveryDiagnostic[] = result.diagnostics.filter(
  (d) => d.phase === "observation",
);
```

Observations finish before the boundary returns, so there is no separate
promise to await.

Before preparing expensive content, check static interest:

```ts
if (hooks.subscribes("tool.before")) {
  // Prepare occurrence facts and content, then call hooks.toolBefore(...).
}
```

### Attachments

`ContentSource` and raw stream bodies are replaced by `Attachment`. Generic
`hooks.dispatch` content parts now require an explicit canonical `selection`.

Before:

```ts
parts: [
  { id: "document", kind: "attachment", mediaType: "text/plain", body: stream },
];
// or
body: Attachment.fromStream(stream);
```

After:

```ts
import { Attachment } from "agenthooksprotocol/client";

const turn = await hooks.turnStart({
  turn: { id: "turn-1" },
  trigger: "user",
  items: [
    {
      role: "user",
      parts: [
        {
          id: "document",
          kind: "attachment",
          mediaType: "text/plain",
          body: Attachment.stream(stream),
        },
      ],
    },
  ],
});
await turn.content?.close();
```

`contentSlots` helpers are removed. Pass bindings directly, for example
`contentSources: [{ path: ["items", 0], source: attachment }]`.

### Authentication

`AuthCredential` and `AuthOverrides` were aliases; use `Credential` and
`AuthOptions`. `HooksOptions.auth` now accepts only a `DeliveryAuthProvider`.
Providers made with `auth()` already implement it. A hand-written provider must
implement `credential(context)` and `challenge(context)`.

### `asOperationalError`

Removed, no replacement. If you need the same normalization, write it in your
code:

```ts
import { HookOperationalError } from "agenthooksprotocol";

function toOperational(error: unknown): HookOperationalError {
  return error instanceof HookOperationalError
    ? error
    : new HookOperationalError("IO_ERROR", "Hook delivery failed", {
        cause: error,
      });
}
```

Do not copy the raw error message into the new error if it can contain
credentials.

### Servers

One raw callback that switched on `message.method` is replaced by
event-correlated handler maps. The server owns envelope IDs and protocol
version, and checks replies against the event and the request's grants.

Before:

```ts
import { hooks, effects } from "agenthooksprotocol/server";
import { serveStdio } from "agenthooksprotocol/server/stdio";

await serveStdio((request) =>
  hooks.handle(request, (message) => {
    if (message.method === "hooks/intercept") {
      return { effects: [effects.deny("Blocked by policy")] };
    }
  }),
);
```

After:

```ts
import { hooks, effect, type ServerHandlers } from "agenthooksprotocol/server";
import { serveStdio } from "agenthooksprotocol/server/stdio";

const handlers = {
  intercept: {
    toolBefore(ctx) {
      if (ctx.event.tool.name === "rm")
        return { effects: [effect.deny("Blocked by policy")] };
      return {}; // An empty reply is a valid no-op.
    },
  },
  observe: {
    sessionEnd(ctx) {
      console.error(ctx.event.type);
    },
  },
  capabilities() {
    return { manifest };
  },
} satisfies ServerHandlers;

await serveStdio(handlers);
// In an authenticated HTTP route: await hooks.handle(request, handlers).
```

Intercept handlers must return a reply. Observe handlers return `void`. The
`effect` helpers are camel-cased (`effect.replaceInput`, `effect.mergeInput`,
`effect.returnResult`, `effect.stop`, `effect.continue`, `effect.appendContext`,
and so on) and construct literal values only; they do not grant authority.
