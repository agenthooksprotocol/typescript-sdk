# Agent Hooks Protocol SDK for TypeScript

TypeScript models, JSON codecs, and runtime utilities for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The generated schema API follows the current AHP `draft` snapshot. The `/client` entrypoint provides the configuration-driven `Hooks` API for harness integrations. The root entrypoint provides JSON admission, NDJSON framing, operational errors, and independent runtime helpers; the draft entrypoint provides canonical validation and reference boundary helpers. Node.js 20 or newer is required.

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

Every public AHP schema has a generated TypeScript type plus `parse<Type>` and `encode<Type>` functions. Successful parse results include the typed value, preserved raw JSON, and structural diagnostics.

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
  state,
  Permission,
  type HostCapabilities,
} from "agenthooksprotocol/client";

// Hooks validates registration; JSON.parse alone does not validate it.
const config: unknown = JSON.parse(await readFile("hooks.json", "utf8"));
const capabilities = {
  toolBefore: { intercept: { deny: true } },
} satisfies HostCapabilities;
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
  const denied = result.state.permission === Permission.Deny;
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
is required. Boundary calls return typed settlement, residual actions, and delivery diagnostics; `Hooks`
does not execute or authorize host operations. Keep a client for the harness lifetime
and close it in `finally`.

`result.state` is a detached, deeply frozen projection of the final canonical
pending state, including `permission` and `candidate`. It reflects accepted
composition and initial state without requiring callers to fold effects. Always
check `result.interrupted` before execution; interruption does not authorize work.

`result.state.permission` is the canonical settled permission; `none` is not approval
and `ask` requires host approval. For tool boundaries, `result.event.tool.input`
contains accepted arguments. Caller contracts infer their application type; without
an arguments contract, validate them against the host's tool schema.

`result.event` is the authoritative decoded canonical event and `result.effects`
contains residual typed actions for the harness to enact. Use `event` for edits
and `state.candidate` for returns; do not replay them from receiver evidence.
`result.acceptedResponses` contains complete decoded receiver envelopes in acceptance order, including
omitted fields, opaque extras, and injection delivery timing. Invalid responses
publish no edits or effects; prior accepted responses remain available. Do not
replay responses to reconstruct `result.event` or `result.state`.

### Static subscription interest

Call `hooks.subscribes(event)` with a generated `EventType` before expensive
occurrence or content preparation.
The synchronous lookup uses validated event selectors and the host's configured
modes, including observe-only subscriptions. Registration selectors use exact
names, `*`, or families such as `tool.*`; the query takes one canonical event name. Payload filters are not evaluated:
a matching subscription remains interesting even if its filters might reject the
completed occurrence. Unconfigured canonical events return `false`; TypeScript
rejects unknown names and arbitrary strings.

The lookup performs no delivery, authentication, uploads, or input preparation.
It reports static interest, not permission or a delivery guarantee. A `false`
result means no eligible intercept or observation subscription can consume that
event under this configuration.

```ts
if (hooks.subscribes("tool.before")) {
  // Prepare occurrence facts and content, then call hooks.toolBefore(...).
}
```

### Operation and resource ownership

Awaiting a boundary also waits for its selected, bounded observation deliveries.
Observations cannot change the settled decision. `result.diagnostics` includes both
interception and observation delivery evidence. Filter by `phase` to select
preparation, interception, or observation diagnostics. To run a call concurrently,
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

Literal helpers imported as `effect` from the server entrypoint construct canonical
effects. Event-correlated replies constrain their types; request grants and host
policy still determine whether they may be emitted or enacted.

Host capabilities declare interception controls and observation interest explicitly.
Use plain readonly event declarations checked with `HostCapabilities`:

```ts
const capabilities = {
  toolBefore: { intercept: { deny: true }, observe: true },
  toolAfter: { observe: true },
} satisfies HostCapabilities;
```

Omitted events, delivery modes, controls, and elicitation dimensions grant nothing.
Each event has its own declaration type (for example `ToolBeforeHostCapabilities`
or `SessionEndHostCapabilities`) with an optional boolean `observe`; an empty
entry or `observe: false` is valid and grants nothing.
An interception declaration needs a supported control or facility; elicitation-only
interception can advertise form or URL handling without an effect grant. Fields
are specific to the event: observation-only events cannot declare interception,
and unsupported modification targets are rejected by TypeScript. Count-bearing
flow declarations use `capabilityCount(value)` to validate nonnegative safe integers
once. The SDK assembles canonical grants directly without a JSON roundtrip.

Use `HooksOptions.manifestMetadata` for non-event advertisements: authentication
methods, transports, policy scopes, limits, and opaque extensions. Hooks copies
metadata synchronously. The `events` field is forbidden; typed capabilities
exclusively determine grants and interest. Metadata is not attachment content.

`ReadFileArguments` checks the host's original arguments at compile time. The SDK
models tool input as structural JSON, not as a tool-specific generic schema. If you
grant `modify`, validate the effective `result.event.tool.input` against your own
tool schema before executing it; do not cast it back to `ReadFileArguments` or use
the original arguments as though a rewrite had not occurred. The host is responsible
for tool-specific runtime validation and for enacting any other granted effects.

## Serve hooks over stdio (Node.js)

Use the same event-correlated handler maps for HTTP and stdio:

```ts
import { hooks, effect, type ServerHandlers } from "agenthooksprotocol/server";
import { serveStdio } from "agenthooksprotocol/server/stdio";

const handlers = {
  intercept: {
    toolBefore(ctx) {
      return { effects: [effect.replaceInput({ ...ctx.event.tool.input, limit: 10 }), effect.allow()] };
    },
  },
  observe: {
    sessionEnd(ctx) { console.error(ctx.event.type); },
  },
} satisfies ServerHandlers;

await serveStdio(handlers);
// In an authenticated HTTP route: await hooks.handle(request, handlers).
```

Intercept replies are correlated to their callback event; `{}` is a valid no-op.
Observation callbacks return void and cannot return controls. An optional
`observe.any(ctx)` catch-all receives every validated observe notification whose
event has no observer of its own; narrow it with `ctx.event.type`. The server owns
JSON-RPC envelope IDs and protocol version. It validates complete replies against
the event and the request's dynamic grants; types do not grant execution authority.
Applications own HTTP authentication and routing.

Requests that cannot be served get fixed, credential-free JSON-RPC errors:
`-32601` when no `capabilities` handler is configured, `-32002`
(`unsupported_event`) for an intercept without a handler for its event, `-32004`
(`backend_internal_error`) when a callback throws or returns a result that cannot
be admitted, `-32001` with `data.supported` for an unsupported protocol version,
and `-32603` for SDK-internal failures. Notifications never get a JSON-RPC body:
an observe event without an observer is accepted (HTTP 204, no stdio output),
and a failing observer yields an empty HTTP 500.

`serveStdio(handlers, { stdin?, stdout?, signal? })` defaults to the Node process
streams. Each UTF-8 NDJSON line uses the same validation and envelope core as
`hooks.handle(request, handlers)`.
Nonempty response bodies are written even for error HTTP statuses; empty bodies
(including notification responses) produce no output. Physical CR/LF characters
in response bodies become spaces so each reply occupies one line. Log to stderr,
not stdout.

Serving is sequential and respects output backpressure. The returned promise
resolves after EOF and the final write, without closing stdout or exiting the
process. Use dedicated streams for a serving session. Errors reject the promise
without fabricated replies; failure or abort destroys both streams. Long-running
handlers should honor `request.signal` for cooperative cancellation.

`serveStdio` is imported from `agenthooksprotocol/server/stdio`, not from
`agenthooksprotocol/server`. The Node-only subpath keeps `node:` imports out of
the Web server entrypoint, so edge and browser bundles can import
`agenthooksprotocol/server` without Node built-ins.

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
const count: number = result.event.tool.input.count;
if (result.state.candidate !== null) {
  const answer: string = result.state.candidate.value.answer;
}

const approval = form(Type.Object({ approved: Type.Boolean() }));
const answer = approval.decode({ action: "accept", content: { approved: true } });
```

`ToolBeforeInput<Arguments>` and `ToolBeforeResult<Arguments, Result, Provenance>`
name these typed boundary values. Supplied codecs determine caller-owned output
types; slots without a codec are `unknown`. Canonical wire models and structural codecs
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

A persistent stdio backend has one reader that routes replies by JSON-RPC ID.
Well-formed replies for no pending request are discarded. A malformed frame
(non-JSON, invalid UTF-8, an empty line, or anything that is not one JSON-RPC
response) is discarded too. It fails the request it names, or else the single
in-flight request (stdio calls are serialized), with `HookOperationalError`;
the process keeps running. Three consecutive malformed frames terminate the
backend; the next request starts a new process. Per-event backends still fail
on the first bad frame. Both cases are published, without frame content, as
`StdioDiagnostic` messages on the `node:diagnostics_channel` named by
`STDIO_DIAGNOSTICS_CHANNEL`:

```ts
import { subscribe } from "node:diagnostics_channel";
import { STDIO_DIAGNOSTICS_CHANNEL, type StdioDiagnostic } from "agenthooksprotocol/client";

subscribe(STDIO_DIAGNOSTICS_CHANNEL, (message) => {
  const { backendId, kind, strikes } = message as StdioDiagnostic;
  console.error(`stdio backend ${backendId}: ${kind} frame (${strikes} consecutive malformed)`);
});
```

### Stdio backend environment

Stdio backends do not inherit the host environment. Each child starts with a
minimal base environment copied from the host: `PATH`, `HOME`, `USER`, `LOGNAME`,
`SHELL`, `LANG`, `LC_ALL`, `LC_*`, `TZ`, `TMPDIR`, `TEMP` and `TMP`. On Windows,
`SYSTEMROOT`, `WINDIR`, `COMSPEC`, `PATHEXT`, `USERPROFILE`, `APPDATA`,
`LOCALAPPDATA` and `PROGRAMDATA` are added, and names match case-insensitively.
The registration's stdio `env` entries are then applied as literal values, with
no interpolation, and override base values. Use `env` for backend
configuration, not AHP endpoint credentials. The SDK never logs `env` values.
To give children the full host environment, set `inheritEnvironment: true` in
`HooksOptions` (or in the third `BackendTransport` argument). Registration `env`
still applies on top.

## Packages

- `agenthooksprotocol/client` — configuration-driven harness client, typed event boundaries, and HTTP/stdio delivery
- `agenthooksprotocol` — JSON admission, NDJSON framing, operational errors, and independent runtime helpers
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
synthetic boundary evaluators. Use `/client` for canonical consumer boundaries. The draft API is not a complete production adapter.
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
  if (result.interrupted || result.state.permission === "deny") throw new Error("Turn not permitted");
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
`Attachment.stream(stream)` takes read/cancel ownership of a native stream.
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
sources, independently of `Hooks.close()`. The canonical `result.event` selects
metadata for local attachment bodies; `result.content` holds their owners. `result.content.ids` indexes local attachment IDs, and
`read(id, signal?)` checks metadata and returns a fresh byte copy. Always await
`result.content.close()` in `finally`, even when no bytes are read. Interrupted or
thrown calls clean up sources instead of transferring usable owners. Remote refs
are not resolved by the local content accessor.

See the standalone [file attachment example](packages/sdk/examples/file-attachment.mjs)
for lazy file loading, direct host construction, and reading after shutdown.
