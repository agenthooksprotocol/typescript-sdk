# Agent Hooks Protocol SDK for TypeScript

TypeScript models, JSON codecs, and runtime utilities for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The generated schema API follows the current AHP `draft` snapshot. The `/client` entrypoint provides the configuration-driven `Hooks` API for harness integrations. The root entrypoint retains the legacy deny/no-effect `tool.before` runner; the draft entrypoint adds canonical validation and reference boundary helpers. Node.js 20 or newer is required.

## Installation

The packages are not yet published to npm. Clone the workspace to use the current draft:

```sh
git clone https://github.com/agenthooksprotocol/typescript-sdk.git
cd typescript-sdk
corepack enable
pnpm install
pnpm build
```

## Parse and encode protocol messages

Schema-derived APIs are exposed through `@agenthooksprotocol/sdk/generated` so they do not collide with the higher-level runtime API.

```ts
import {
  encodeCapabilities,
  parseCapabilities,
} from "@agenthooksprotocol/sdk/generated";

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

Use `@agenthooksprotocol/sdk/client` for new harness integrations. Store a registration
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
} from "@agenthooksprotocol/sdk/client";

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
against the host's tool schema. `result.event` and `result.response` remain available.

### Operation and resource ownership

Awaiting a boundary also waits for its selected, bounded observation deliveries.
Observations cannot change the settled decision. `result.diagnostics` includes both
interception and observation delivery failures; the compatibility `observations`
promise is already settled when the boundary returns. To run a call concurrently,
retain its promise in the harness. Do not execute a gated operation before that
promise settles and its permission, interruption, and host-validation gates pass.

Pass `signal: AbortSignal.timeout(milliseconds)` for one outer operation budget,
or a host-owned cancellation signal. Queue waits, authentication, selected content,
uploads, retries, and observations share that signal. Existing subscription/upload
limits can shorten it, never reset it. Cancellation stops new delivery work; SDK
child processes are reaped before operation cleanup completes. Safety cleanup can
extend beyond the deadline. `close()` cancels active calls and releases SDK-owned
resources, is repeatable, and rejects subsequent calls. It does not close shared
providers or injected HTTP adapters. Await active calls first if graceful completion
is wanted; close does not implicitly drain normal observation processing.

Wrap owned streams as `new ContentSource(stream)` (imported from the client entry
point), then place the source in a content item's `body`. Construction does no I/O.
Metadata/omit/unmatched routes do not read bytes; selected body deliveries snapshot
once under the configured limit and upload independently to authorized destinations.
The SDK computes size/hash and verifies receiver descriptors before publishing the
event. Calling a boundary transfers read/cancel ownership, including unused and
failed-call paths. Native raw streams and canonical references remain supported.
Keep host execution data separately from these owned delivery sources.

Alternatively, keep a metadata descriptor in a generated input and pass
`contentSources: [contentSlots[events.toolBefore].items(0, source)]` as boundary
options. The generated slot binds the owned source to that descriptor without a
caller-created ref. Only authorized body selection promotes it to a verified
receiver-allocated reference; metadata and omit selections never read it.

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
never fall back to event credentials. Existing `auth()` discovery/exchange helpers
remain optional conveniences; TLS/network policy stays in the trusted HTTP adapter.

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

Omitted events and modes grant nothing. Full static manifests remain supported.
Effect grants and elicitation `form`/`url` grants must also be explicit.

`ReadFileArguments` checks the host's original arguments at compile time. The SDK
models tool input as structural JSON, not as a tool-specific generic schema. If you
grant `modify`, validate the effective `result.input` against your own
tool schema before executing it; do not cast it back to `ReadFileArguments` or use
the original arguments as though a rewrite had not occurred. The host is responsible
for tool-specific runtime validation and for enacting any other granted effects.

## Legacy `ToolBeforeRunner`

```ts
import { ToolBeforeRunner } from "@agenthooksprotocol/sdk";

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
import { hooks } from "@agenthooksprotocol/sdk/server";
import { serveStdio } from "@agenthooksprotocol/sdk/server/stdio";

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
`hooks.handle` remains responsible for validation and response correlation.
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

## Packages

- `@agenthooksprotocol/sdk/client` — configuration-driven harness client, typed event boundaries, and HTTP/stdio delivery
- `@agenthooksprotocol/sdk` — legacy hook runner, stdio transport, runtime types, and operational errors
- `@agenthooksprotocol/sdk/generated` — schema-derived models and structural codecs
- `@agenthooksprotocol/sdk/draft` — canonical draft validators, generated models, and reference boundary helpers
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

Generated code lives in `packages/sdk/src/generated.ts`. Its provenance is recorded in `ahp-codegen.lock.json`; schema changes are made in the [protocol repository](https://github.com/agenthooksprotocol/agent-hooks-protocol), not by editing the generated file.

## Draft API

`@agenthooksprotocol/sdk/draft` exposes generated models and codecs for the full
canonical draft catalogue, schema-backed validators, content-upload helpers, and
synthetic boundary evaluators. This does **not** expand `ToolBeforeRunner` beyond
its deny/no-effect `tool.before` slice or provide a complete production adapter.
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
