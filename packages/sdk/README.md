# Agent Hooks Protocol SDK for TypeScript

TypeScript models, JSON codecs, and runtime utilities for the
[Agent Hooks Protocol](https://github.com/agenthooksprotocol/agent-hooks-protocol).
Requires Node.js 20 or newer. The schema API follows the current AHP `draft` snapshot.

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

`hooks.intercepts(event)` is `subscribes` restricted to intercept subscriptions.
Use it to decide whether to withhold streamed output until interceptors settle.

```ts
const withhold = hooks.intercepts("model.response.after");
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
observations return void. An optional `observe.any(ctx)` catch-all receives
observations for events without their own observer. Import `serveStdio` from
the Node-only `agenthooksprotocol/server/stdio` subpath; the main
`agenthooksprotocol/server` entry has no `node:` imports. Complete reply effects retain their order and opaque
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

## HTTP registration headers

HTTP backends can set headers in `transport.headers`. The configuration applies to
that backend's event POSTs and content uploads, not other backends or OAuth
metadata/token endpoints:

```json
{
  "type": "http",
  "url": "https://policy.example/hooks",
  "headers": {
    "Authorization": "Bearer abc123",
    "Cookie": "session=example",
    "X-Api-Key": { "valueEnv": "POLICY_API_KEY" },
    "X-Gateway-Token": { "valueRef": "secrets/policy-gateway" }
  }
}
```

All valid HTTP field names are supported, including `Authorization`, `Cookie`,
`Origin`, `Content-Type` and protocol headers. Literal credentials are supported.
Names and values are validated with Node's HTTP validators and the fetch
`Headers` API: injection is rejected, while supported non-ASCII values are
accepted. Native HTTP limits still apply; the SDK adds no custom header-size cap.

Case-insensitive duplicate names use the **last property in configuration
iteration order**. Each request starts with transport defaults and authentication
headers, then applies the configured values last, case-insensitively. Configured
`Authorization`, in any casing and from any source, suppresses credential
acquisition, OAuth discovery, challenge handling and authentication retries for
both events and uploads, even when authentication is also configured. A missing
or invalid explicit authorization source fails the delivery; it never falls back
to another identity.

Header sources reuse the authentication provider's existing secret resolvers:

```ts
const provider = auth({
  resolveEnvironmentVariable: name => process.env[name],
  resolveCredentialReference: (reference, context) => vault.read(reference, {
    backendId: context.backendId,
    url: context.url,
    signal: context.signal,
  }),
});
const hooks = new Hooks(registration, { ...options, auth: provider });
```

The resolver context identifies the backend, actual destination, delivery purpose
(`event` or `upload`) and the cancellation signal carrying its deadline. Sources
resolve once per delivery operation and are reused by existing authentication
retries; subsequent operations resolve again for rotation. Environment defaults
read the harness environment, not a stdio child's environment. Missing, empty or
failed source values fail closed; diagnostics omit values and resolver exceptions.
`BackendTransportOptions.auth` accepts the same secret resolver methods for
standalone transports; its fetch adapter continues to own authentication.

Registration headers do not change existing redirect behavior. These SDK
transports already use `redirect: "error"`, with or without configured headers.
No global HTTP-client defaults are changed.

## Authentication routing

`auth(overrides)` and custom `DeliveryAuthProvider` implementations remain supported.
Use `auth.compose` when different bindings need different providers. Installing an
OAuth provider does not replace native bearer resolution:

```ts
import { auth, AuthError, Hooks } from "agenthooksprotocol/client";

const provider = auth.compose({
  bearer: auth.bearer({
    resolveCredentialReference: (reference, context) => vault.read(reference, {
      signal: context.signal,
    }),
  }),
  oauth: hostOAuth,
  discover: hostOAuth,
});
const hooks = new Hooks(registration, { ...options, auth: provider });
```

The host supplies `vault`, `hostOAuth`, registration and other Hooks options.
Each route implements the existing `credential(context)` and `challenge(context)`
contract. Methods retain their receiver; callers need not use `this` or
`context.provider` to compose routes. The bearer route defaults to `auth()`.
There is no default OAuth route: configured OAuth without one fails with
`unsupported_binding`, for both PKCE and client credentials. Missing credentials
fail with `credential_unavailable`; routes never fall back to another provider.
An explicit Authorization header still bypasses provider authentication.

Without a binding, the first attempt remains anonymous. Only a subsequent
challenge invokes `discover`; omit that route to disable automatic discovery.
Uploads and events select routes from their own bindings. Challenges return to
the provider that issued the exact opaque attempt, with its original credential;
the router never refreshes or replays HTTP requests itself.

`normalizeAuthTarget(context)` returns a frozen, readonly discriminated target
(`bearer`, `oauth`, or `discover`) without resolving credentials or doing I/O. It
validates local structure, not destination trust. Providers still own destination,
issuer, resource, scope and client policy. `AuthError` exposes safe `code` and
`recovery` fields (`configure`, `login`, `retry`, or `none`). For example, a host
provider can throw `new AuthError("interaction_required")` to request login.
Recovery is guidance, never permission to replay an effectful delivery.

Routed provider exceptions become redacted `AuthError`s without cause chains.
Native caller cancellation is preserved, including `AbortSignal.reason`.
Providers and stores must honor that signal: stopping the wait cannot cancel work
that ignores it. Configured-header resolver methods retain the existing safe
header error boundary. The same helpers and types are explicitly exported from
`agenthooksprotocol/client/auth`.

### Existing OAuth and managed adapter status

The existing `auth({ selectClient, authorize, ... })` helper still supports
host-driven PKCE, client credentials, discovery and refresh. It can be explicitly
installed as the `oauth` and `discover` routes:

```ts
const hostOAuth = auth({
  selectClient: (issuers, resource, context) => trustedClients.select(issuers, resource, context),
  authorize: (request, context) => hostLogin.completeCallback(request, context),
});
const provider = auth.compose({ oauth: hostOAuth, discover: hostOAuth });
```

Here `trustedClients` is host policy and `hostLogin` owns consent/callback
transport, returning the complete callback URL and honoring `request.signal`.
Client-credentials bindings do not invoke `authorize`; resolve their configured
client secret through the existing `resolveCredentialReference` option. The host
also owns secret resolution and policy. Composition creates no browser,
listener, worker or file store, and does not introduce another OAuth engine.

An optional library-backed managed OAuth package is **not shipped** here.
`oauth4webapi` 3.8.8 exposes discovery, PKCE, authorization-response validation,
both token grants, refresh and custom fetch hooks, with ESM/Node 20 metadata.
API inspection is not runtime security parity. Migration is blocked on preserving
MCP protected-resource discovery/fallback, RFC 9728 resource validation, exact
issuer and local scope policy, RFC 8707 resource-bound exchange, and DNS/redirect
policy at every network boundary. It also needs namespace-isolated structural
stores, generation-aware stale rejection, coordinated refresh/login, transient
refresh retention, and host-controlled prepare/complete interaction tests.
Existing APIs remain until both flows, cancellation and redaction have parity;
this router does not provide those managed lifecycle guarantees.

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

## Restricted runtimes

The client runs where code generation is refused (`eval`, `new Function`) and
Node is absent, such as a sandboxed plugin host. Canonical validators are
precompiled at build time (`scripts/compile-validators.mjs`) into modules under
512 KiB each; caller contracts fall back to TypeBox's interpreter when the
runtime refuses generated code. A host without Node supplies its own I/O:

```ts
const hooks = new Hooks(config, {
  source: "urn:example:sandboxed-agent",
  harness: { name: "sandboxed-agent", version: "1.0.0" },
  capabilities,
  fetch: hostFetch,            // any WHATWG-compatible fetch
  spawn: (request) => launch(request), // StdioProcess for stdio backends
  environment: {},             // the base environment stdio backends draw from
});
```

`spawn` receives `{ command, args, cwd?, env }`, with `env` already the complete
environment the backend should see, and returns a `StdioProcess`
(`write(data, end, callback)`, `onStdout`, `onError`, `onClose`, `kill`).
The default launcher, `nodeSpawn`, uses `node:child_process`.

## License

Apache-2.0. See [LICENSE](LICENSE).
