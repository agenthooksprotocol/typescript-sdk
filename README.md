# Agent Hooks Protocol SDK for TypeScript

TypeScript models, JSON codecs, and runtime utilities for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The generated schema API follows the current AHP `draft` snapshot. The `/client` entrypoint provides the configuration-driven `Hooks` API for harness integrations. The root entrypoint provides the deny/no-effect `tool.before` runner; the draft entrypoint provides canonical validation and reference boundary helpers. Node.js 20 or newer is required.

## Installation

```sh
npm install agenthooksprotocol
```

Only the SDK is published. The testing and conformance packages are private
workspace tools. See [RELEASE.md](RELEASE.md) for release setup and maintenance.

## Parse and encode protocol messages

Schema-derived APIs are exposed through `agenthooksprotocol/generated` so they do not collide with the higher-level runtime API.

```ts
import {
  encodeCapabilities,
  parseCapabilities,
} from "agenthooksprotocol/generated";

const result = parseCapabilities(
  '{"effects":["deny"],"com.example.preview":true}',
);

if (!result.ok) {
  throw new Error(JSON.stringify(result.diagnostics));
}

console.log(result.value.effects);
const encoded = encodeCapabilities(result.value);
```

Every public AHP schema has a generated TypeScript type plus `parse<Type>` and `encode<Type>` functions. Successful parse results include the typed value, preserved raw JSON, and compatibility diagnostics.

## Intercept a tool call with `Hooks`

Use `agenthooksprotocol/client` for harness integrations. Store a registration
in `hooks.json` (replace the URL with your hook backend):

```json
{
  "protocolVersion": "draft",
  "hooks": [
    {
      "id": "example.policy",
      "transport": { "type": "http", "url": "https://hooks.example/intercept" },
      "subscriptions": [
        {
          "mode": "intercept",
          "events": ["tool.before"],
          "includeNative": true,
          "timeoutMs": 2000,
          "failurePolicy": "fail-closed",
          "content": { "default": "metadata" }
        }
      ]
    }
  ]
}
```

The host loads that JSON and explicitly grants the backend permission to deny.
This TypeScript example uses Node.js types (`@types/node`):

```ts
import { readFile } from "node:fs/promises";
import {
  Hooks,
  capabilities as capability,
  events,
  state,
  Permission,
  type EventCapabilities,
} from "agenthooksprotocol/client";

// Hooks validates registration; JSON.parse alone does not validate it.
const config: unknown = JSON.parse(await readFile("hooks.json", "utf8"));
const capabilities: EventCapabilities = {
  [events.toolBefore]: capability.intercept().deny(),
};
const hooks = new Hooks(config, {
  source: "urn:example:agent",
  capabilities,
});

type ReadFileArguments = { path: string };
const args: ReadFileArguments = { path: "README.md" };

try {
  // Boundary calls wait for initialization internally.
  const result = await hooks.toolBefore(
    {
      callId: "read-1",
      path: "native",
      name: "read_file",
      origin: "native",
      input: args,
    },
    { initialState: state.initial(Permission.None) },
  );

  for (const diagnostic of result.diagnostics) console.error(diagnostic);
  const denied = result.permission === Permission.Deny;
  if (result.interrupted || denied) {
    throw new Error("File read interrupted or denied by hooks");
  }

  // Only deny is granted, so hooks cannot rewrite args. The host executes
  // the operation after its own authorization and path checks.
  console.log(await readFile(args.path, "utf8"));
} finally {
  await hooks.close();
}
```

`source` and `capabilities` belong to the constructor. `initialState` is an optional
per-boundary snapshot, not a constructor option. No separate `await hooks.initialized`
is required. Boundary calls return protocol effects and delivery errors; `Hooks`
does not execute or authorize host operations. Keep a client for the harness lifetime
and close it in `finally`.

`result.state` is a detached, deeply frozen projection of the final canonical
pending state, including `permission` and `candidate`. It reflects accepted
composition and initial state without requiring callers to fold effects. Always
check `result.interrupted` before execution; interruption does not authorize work.

`result.permission` reads that canonical settled permission; `none` is not approval,
`ask` requires host approval, and an interrupted result is not executable. For tool
boundaries, `result.input` exposes accepted arguments as `unknown`; validate them
against the host's tool schema. `result.event` and `result.response` expose the effective event and protocol response.

### Operation and resource ownership

Awaiting a boundary also waits for its selected, bounded observation deliveries.
Observations cannot change the settled decision. `result.diagnostics` includes both
interception and observation delivery failures; the `observations`
promise is already settled when the boundary returns. To run a call concurrently,
retain its promise in the harness. Do not execute a gated operation before that
promise settles and its permission, interruption, and host-validation gates pass.

Pass `signal: AbortSignal.timeout(milliseconds)` for one outer operation budget,
or a host-owned cancellation signal. Queue waits, authentication, selected content,
uploads, retries, and observations share that signal. Subscription/upload
limits can shorten it, never reset it. Cancellation stops new delivery work; SDK
child processes are reaped before operation cleanup completes. Safety cleanup can
extend beyond the deadline. `close()` cancels active calls and releases SDK-owned
resources, is repeatable, and rejects subsequent calls. It does not close shared
providers or injected HTTP adapters. Await active calls first if graceful completion
is wanted; close does not implicitly drain normal observation processing.

Canonical messages contain a role and ordered `parts`. Text is inline in a
`{ kind: "text", text: "..." }` part. Serialize structured text with
`JSON.stringify(value)`; JSON is text, not an attachment part. Binary attachment
parts carry `kind: "attachment"`, a non-text/non-JSON `mediaType`, and an
`Attachment` in `body`. Normal named `Hooks` methods construct canonical identity
and collect attachment ownership internally; callers do not create wire refs or
project host inputs.

Body-selected text is delivered inline. Metadata and omit selections remove both
text and attachment bodies. Unmatched routes do not open attachments. Each
body-selected destination uploads from the exact attachment owner and receives a
verified receiver-allocated reference. The owner materializes at most once under
the invocation's aggregate byte limit. Conversion performs no reads or uploads.
Only schema-owned slots are inspected; native and provider-specific payloads are
opaque. Calling a boundary transfers attachment cleanup ownership, including
unused and failed-call paths. Keep host execution data separately.

`user.elicitation.request` and `user.elicitation.result` carry JSON serialized in
inline text parts. Selected requests retain bounded correlation facts for matching
results by parent event, source, session, mode, and server. Denial, failed or
interrupted delivery, a result attempt, session end, and `close()` retire the
exchange. Call `hooks.discardElicitation(requestEventId)` when abandoning a pending
exchange. Other pending exchanges are not evicted when the exchange count or byte
budget is exceeded.

Message and text-list replacement substitutes the supplied list; merge appends
in order. Object-target merge is shallow. Each response is admitted atomically,
and later interceptors receive the effective event after accepted edits. Binary
attachment bodies are immutable and are not text-edit targets.

### Harness-owned authentication

`HooksOptions.auth` accepts a small `DeliveryAuthProvider`: `credential(context)`
returns `{ type: "bearer", token, attempt? }`, and `challenge(context)` handles an
actual 401 response before the one bounded retry. Context includes the selected
registration authentication binding, backend ID, destination URL, event/upload
purpose, and operation signal. Challenge context also contains the exact attempted
credential, including its opaque identity, for stale-token rejection handling.
Requests retain their identity and prepared body across recovery.

The provider owns secret lookup, discovery/trust policy, OAuth login/exchange,
rotation, shared coordination and persistence. Callbacks must honor their signal;
cancelling one wait does not authorize cancelling other callers' shared work.
Absent bindings start anonymously and may use challenge-driven discovery under the
host's trust policy. Configured missing credentials fail closed. Upload bindings
never fall back to event credentials. The `auth()` discovery/exchange helpers
are optional; TLS/network policy belongs in the trusted HTTP adapter.

Generated `capability.intercept()` deliberately advertises both interception and
observation; `capability.observe()` advertises observation only. Builders compose
without mutating reused declarations, and host boundary compatibility is checked
before delivery. Effect helpers imported as `effects` from the server entry point
construct canonical effects; they never grant permission to emit those effects.

Raw capability declarations never infer observation authority. A plain event value
such as `{ effects: ["deny"] }` grants interception only. Use explicit `modes`
when the harness supports observations, including fallback notifications after a
normal short-circuit:

```ts
const capabilities: EventCapabilities = {
  "tool.before": {
    modes: ["intercept", "observe"],
    capabilities: { effects: ["deny"] },
  },
  "tool.after": { modes: ["observe"] },
};
```

Omitted events and modes grant nothing. Full static manifests are also supported.
Effect grants and elicitation `form`/`url` grants must also be explicit.

`ReadFileArguments` checks the host's original arguments at compile time. The SDK
models tool input as structural JSON, not as a tool-specific generic schema. If you
grant `modify`, validate the effective `result.input` against your own
tool schema before executing it; do not cast it back to `ReadFileArguments` or use
the original arguments as though a rewrite had not occurred. The host is responsible
for tool-specific runtime validation and for enacting any other granted effects.

## `ToolBeforeRunner`

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

if (outcome.decision === "deny") {
  console.error(outcome.denial?.reason);
}

unregister();
```

Backends use UTF-8 NDJSON over stdin and stdout. Commands and argument arrays are passed directly to `spawn` without a shell. Both per-event and persistent process lifecycles are supported.

## Serve hooks over stdio (Node.js)

Keep the same Web `Request`/`Response` handler for HTTP and stdio:

```ts
import { hooks } from "agenthooksprotocol/server";
import { serveStdio } from "agenthooksprotocol/server/stdio";

await serveStdio((request) =>
  hooks.handle(request, (message) => {
    if (message.method === "hooks/intercept") {
      return { effects: [{ type: "deny", reason: "Blocked by policy" }] };
    }
    // Observe callbacks return void. Add a manifest for hooks/capabilities
    // when this backend supports discovery.
  }),
);
```

`serveStdio(handler, { stdin?, stdout?, signal? })` defaults to the Node process
streams. Each UTF-8 NDJSON line becomes a POST `Request` with an
`application/json` body; the shim does not parse or validate JSON-RPC.
`hooks.handle` performs validation and response correlation.
Nonempty response bodies are written even for error HTTP statuses; empty bodies
(including notification responses) produce no output. Physical CR/LF characters
in response bodies become spaces so each reply occupies one line. Log to stderr,
not stdout.

Serving is sequential and respects output backpressure. The returned promise
resolves after EOF and the final write, without closing stdout or exiting the
process. Use dedicated streams for a serving session. Errors reject the promise
without fabricated replies; failure or abort destroys both streams. Long-running
handlers should honor `request.signal` for cooperative cancellation. The Node-only subpath keeps `node:` imports out of the
Web server entrypoint.

## Typed caller contracts

Use `Type`, `contract`, and `form` from `agenthooksprotocol/client` to declare
application payloads. Schema inference stays attached to the contract; call its
`decode` method when admitting application data directly.

```ts
import { Hooks, Type, contract, form } from "agenthooksprotocol/client";

const argumentsContract = contract(Type.Object({ count: Type.Integer() }));
const resultContract = contract(Type.Object({ answer: Type.String() }));
const argumentsValue = argumentsContract.decode({ count: 1 });

// hooks is a configured Hooks instance with explicit tool.before grants.
declare const hooks: Hooks;
const result = await hooks.toolBefore({
  callId: "call-1", name: "read", path: "native", origin: "native",
  input: argumentsValue,
}, { contracts: { arguments: argumentsContract, result: resultContract } });
const count: number = result.input.count;
if (result.state.candidate !== null) {
  const answer: string = result.state.candidate.value.answer;
}

const approval = form(Type.Object({ approved: Type.Boolean() }));
const answer = approval.decode({ action: "accept", content: { approved: true } });
```

`ToolBeforeInput<Arguments>` and `ToolBeforeResult<Arguments, Result, Provenance>`
name these typed boundary values. Canonical wire models and structural codecs
remain available from `/draft` and `/generated`.

### Advanced delivery APIs

`ContentManager` and `BackendTransport` are intentional advanced `/client` APIs
for hosts implementing their own delivery orchestration. Prefer `Hooks` for normal
boundary calls. A `ContentManager` coordinates one invocation's attachment owners,
byte budget, uploads, and cleanup; immutable bytes and lazy sources belong to
`Attachment`, not to the manager. Close the manager after the invocation. Transfer
returned content ownership before closing when results must outlive delivery.
`ContentManagerOptions` configures `maxSnapshotBytes`, `maxConcurrentUploads`
(default `8`), and `allowLoopback`. Standalone managers have independent upload
limits; `Hooks` shares its upload limit across its concurrent invocations.

`BackendTransport` implements HTTP/stdio delivery for a canonical `Backend` and a
caller-supplied fetch adapter. The adapter owns network policy and authentication;
close the transport to release its processes and pending requests. Transport
handling validates envelopes, not application contracts or boundary admission.

## Packages

- `agenthooksprotocol/client` — configuration-driven harness client, typed event boundaries, and HTTP/stdio delivery
- `agenthooksprotocol` — hook runner, stdio transport, runtime types, and operational errors
- `agenthooksprotocol/generated` — schema-derived models and structural codecs
- `agenthooksprotocol/draft` — canonical draft validators, generated models, and reference boundary helpers
- `@agenthooksprotocol/testing` — configurable fake backend for integration tests
- `@agenthooksprotocol/conformance` — black-box conformance runner and CLI

## Development

The interop tests require a sibling `../agent-hooks-protocol` checkout. CI pins its
shared fixtures to `548f1e857ba3f4d803fc40b04f848236b7316704`. The workspace
installs its TypeScript compiler and canonical validator dependencies.

```sh
pnpm install --frozen-lockfile
pnpm check
```

Run the local conformance target:

```sh
node packages/conformance/dist/src/cli.js -- \
  node packages/testing/dist/src/fake-backend.js --mode no-effect
```

The current draft contracts live in `packages/sdk/src/draft/`. The advanced `/generated` entrypoint exposes the filtered `draft/codecs.ts` facade; `/draft` adds canonical validation and the explicit `reference` namespace. Generated provenance is recorded in `packages/sdk/src/draft/ahp-codegen.lock.json`; schema changes are made in the [protocol repository](https://github.com/agenthooksprotocol/agent-hooks-protocol), not by editing generated files.

## Draft API

`agenthooksprotocol/draft` exposes generated models and codecs for the full
canonical draft catalogue, schema-backed validators, content-upload helpers, and
synthetic boundary evaluators. `ToolBeforeRunner` supports only the deny/no-effect
`tool.before` slice. The draft API is not a complete production adapter.
See the [draft API guide](packages/sdk/DRAFT-API.md) for entrypoints and limits.

The protocol authority is the sibling repository's
[`spec/draft`](../agent-hooks-protocol/spec/draft/index.md) and
[`schema/draft`](../agent-hooks-protocol/schema/draft/manifest.json), not this SDK
or its test fixtures. Subscriptions and their IDs are local dispatch configuration;
they are not wire identity, including in candidate provenance or upload headers.

## Synthetic interoperability harness (test-only)

`pnpm interop` builds and runs the synthetic interoperability CLI. `pnpm check`
builds the workspace and runs package tests plus `interop/*.test.mjs`. These tests
exercise fixture-defined transport, authentication, and boundary behavior; they
are not certification of the complete protocol or production authentication.
Fixture credentials and keys are public test material, never deployment secrets.
Local dispatch IDs and harness state must not be copied into protocol payloads.

## License

Apache-2.0

## Owned attachments

Import `Attachment` from `agenthooksprotocol/client` for invocation-owned binary
content. Use a normal boundary method with direct host facts:

```ts
import { Attachment, Hooks } from "agenthooksprotocol/client";

// hooks is a configured Hooks instance with explicit turn.start grants.
const attachment = Attachment.bytes(new Uint8Array([1, 2, 3]));
const result = await hooks.turnStart({
  turn: { id: "turn-1" },
  trigger: "user",
  items: [{
    role: "user",
    parts: [
      { kind: "text", text: "Inspect this binary document." },
      { id: "document", kind: "attachment", mediaType: "application/octet-stream", body: attachment },
    ],
  }],
});
try {
  if (result.interrupted || result.permission === "deny") throw new Error("Turn not permitted");
  await hooks.close();
  const bytes = await result.content?.read("document");
} finally {
  await result.content?.close();
}
```

`Attachment.bytes` defensively copies its input. `Attachment.lazy(open, dispose?)`
opens at most once on byte demand; `open` returns a `Uint8Array` or its promise and
must honor its abort signal. The optional asynchronous `dispose` releases producer
resources, including unopened sources, and must finish promptly.
`Attachment.fromStream(stream)` takes read/cancel ownership of a native stream.
Apply producer-side bounds when loading files: `maxContentBytes` bounds retained
SDK bytes, not allocations inside a caller's loader.

Authorized attachment body selections are planned before the serial interceptor
chain. Each immutable owner is materialized once and uploaded concurrently to its
requesting subscriptions. `HooksOptions.maxConcurrentUploads` is a positive integer
with default `8` (the shared SDK option is `max_concurrent_uploads` /
`maxConcurrentUploads`). The limit is shared across all concurrent calls on the same
`Hooks` instance. Each slot covers upload preparation (including materialization)
through transfer and receipt confirmation. Local result reads do not acquire
upload slots. Confirmed references are isolated by backend and subscription,
even when upload URLs are equal. Inline text does not upload; metadata-only, omitted,
and unmatched attachments remain unread. Removing an attachment during interception
does not undo its planned upload. Preparation failures are handled at the affected
subscription's delivery point, using its failure policy; observers are best effort.

Overlapping reads join the same immutable result or source error. Cancelling one
waiter does not cancel another waiter's materialization. Invocation or last-owner
cleanup releases the source. Results remain readable after `hooks.close()` until
`result.content.close()`.

`Attachment.read(signal?)` returns a defensive copy. Do not read an attachment
before handing it to an invocation, or reuse it in another invocation. Once passed
to a boundary, let `result.content` manage cleanup. Explicit IDs must be
unambiguous; omitted message and part IDs receive synthesized canonical identities.

A successful non-interrupted result retains the actual owners, including unread
sources, independently of `Hooks.close()`. `result.event` attachment bodies refer
to those same owners. `result.content.ids` indexes local attachment IDs, and
`read(id, signal?)` checks metadata and returns a fresh byte copy. Always await
`result.content.close()` in `finally`, even when no bytes are read. Interrupted or
thrown calls clean up sources instead of transferring usable owners. Remote refs
are not resolved by the local content accessor.

See the standalone [file attachment example](packages/sdk/examples/file-attachment.mjs)
for lazy file loading, direct host construction, and reading after shutdown.
