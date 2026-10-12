# Agent Hooks Protocol SDK for TypeScript

TypeScript models, JSON codecs, and runtime utilities for the
[Agent Hooks Protocol](https://github.com/agenthooksprotocol/agent-hooks-protocol).
Requires Node.js 20 or newer. The schema API follows the current AHP `draft` snapshot.
Upgrading from 0.4? See the
[migration guide](https://github.com/agenthooksprotocol/typescript-sdk/blob/main/MIGRATING.md).

```sh
npm install agenthooksprotocol
```

```ts
import { parseCapabilities } from "agenthooksprotocol/generated";

const result = parseCapabilities('{"effects":["deny"]}');
if (!result.ok) throw new Error(JSON.stringify(result.diagnostics));
console.log(result.value.effects);
```

Use `agenthooksprotocol/client` for the configuration-driven `Hooks` API,
`agenthooksprotocol/server` for hook backends, and `agenthooksprotocol/draft`
for canonical validation and reference boundary helpers. `/generated` exposes
the filtered codecs for those same current draft contracts; it is not a separate
wire version.

See the [SDK documentation and examples](https://github.com/agenthooksprotocol/typescript-sdk#readme)
for all entrypoints and integration guidance. Consumer results expose one typed
`event`, settled `state`, residual `effects`, complete `acceptedResponses`, and
structured `diagnostics`. Use `event` for settled edits and `state.candidate` for
returns; `effects` contains only the remaining actions to enact. Full receiver
effects remain in `acceptedResponses`. Local attachment bytes are read through `result.content`;
callers close that content owner explicitly. The testing and conformance
workspace packages are not published.

## Static subscription interest

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

## Typed host capabilities and server handlers

Declare capabilities as plain objects checked by `HostCapabilities`:

```ts
import type { HostCapabilities } from "agenthooksprotocol/client";
const capabilities = {
  sessionStart: { observe: true },
  toolBefore: {
    intercept: { allow: true, deny: true, returnResult: true, modifyInput: "replace-and-merge" },
    observe: true,
  },
} satisfies HostCapabilities;
```

Event-specific fields exclude unsupported controls and require at least one
interception control or facility, or explicit observation. The SDK transfers
these typed declarations directly into canonical grants without JSON reparsing.
Use `capabilityCount` for dependent flow counts. Dynamic request grants and host
execution permission remain runtime checks.

`HooksOptions.manifestMetadata` supplies non-event advertisements such as
authentication methods, transports, policy scopes, limits, and opaque extensions.
Hooks owns a synchronous copy. Metadata cannot contain `events`; generated
capability declarations exclusively determine event grants and subscription
interest. Opaque metadata is not traversed as attachment content.

Server callbacks use separate event-correlated phase maps:

```ts
import { effect, type ServerHandlers } from "agenthooksprotocol/server";
const handlers = {
  intercept: {
    toolBefore(ctx) {
      return { effects: [effect.replaceInput({ ...ctx.event.tool.input, limit: 10 }), effect.allow()] };
    },
  },
  observe: { sessionEnd(ctx) { console.error(ctx.event.type); } },
} satisfies ServerHandlers;
```

Pass this object to `hooks.handle(request, handlers)` for HTTP or
`serveStdio(handlers, options)` for stdio. Both share canonical admission and
server-owned envelope correlation. Empty intercept replies are valid no-ops;
observations return void. Complete reply effects retain their order and opaque
extensions. Applications own authentication and routing.

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

## Structural decoding and effect-family queries

Use `draftCodecs.parseInterceptRequest(input)` (and the other generated `parse*`
functions) from `agenthooksprotocol/draft` for runtime structural decoding of JSON
text or JSON-compatible objects. A type assertion or native `JSON.parse` alone
is **not** an SDK decoding boundary. The parser checks the original composed
schema descriptor once; it does not reconstruct and revalidate each child model.
Its discriminated `ParseResult` retains diagnostics, raw JSON, extension fields,
and structural warnings, including unknown event variants and open enums.
Structural decoding preserves unknown data without granting it semantics; it is not complete canonical validation
or contextual admission. The draft `validate*` APIs additionally apply canonical
JSON Schema validation and have a different, narrower result shape.

```ts
import { draftCodecs, effectNames, supports } from 'agenthooksprotocol/draft';
const parsed = draftCodecs.parseInterceptRequest(text);
if (parsed.ok && supports(parsed.value.params.capabilities, effectNames.deny)) {
  // The sender advertised the deny family. This does not authorize execution.
}
```

`effectNames` and `supports` are also exported from `/client` and `/server`.
`supports({effects: [...]}, family)` accepts schema-derived identifiers and custom
string identifiers. It tests only explicit membership: nested target/operation
grants do not imply family membership, and a positive result does not prove
mode, per-call, target, operation, or execution permission.

Missing state candidates and candidates with missing `value` are rejected.
`candidate: null` means no candidate; `{value: null}`, `{value: 0}`, and
`{value: false}` remain distinct present candidates. Integer schema positions
accept safe JavaScript integers and `bigint`. SDK JSON codecs preserve integer
tokens outside the safe range as `bigint`; native `JSON.parse` does not. Non-finite
numbers are rejected. Use SDK encoders to serialize lossless integer values.

Object-input parsing requires plain JSON data. Class instances, sparse arrays,
cycles, accessors, and non-JSON properties are rejected. Generated model aliases
are static types; constructors and helpers do not claim runtime validation or
authorization. Native untyped decoding is outside this contract.

## License

Apache-2.0. See [LICENSE](LICENSE).
