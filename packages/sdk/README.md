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
for all entrypoints and integration guidance. The testing and conformance
workspace packages are not published.

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

## License

Apache-2.0. See [LICENSE](LICENSE).

### Structural decoding and effect-family queries

Use `draftCodecs.parseInterceptRequest(input)` (and the other generated `parse*`
functions) from `agenthooksprotocol/draft` for runtime structural decoding of JSON
text or JSON-compatible objects. A type assertion or native `JSON.parse` alone
is **not** an SDK decoding boundary. The parser checks the original composed
schema descriptor once; it does not reconstruct and revalidate each child model.
Its discriminated `ParseResult` retains diagnostics, raw JSON, extension fields,
and compatibility warnings, including unknown event variants and open enums.
This is structural compatibility validation, not complete canonical validation
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
require JavaScript safe integers. Arbitrary JSON numbers use finite IEEE-754
JavaScript numbers: numeric token spelling and integers above the safe range
cannot be preserved exactly by JavaScript JSON parsing. Non-finite values are
rejected. Use strings for application-owned exact large numeric identifiers.

Object-input parsing requires plain JSON data. Class instances, sparse arrays,
cycles, accessors, and non-JSON properties are rejected. Generated model aliases
are static types; constructors and helpers do not claim runtime validation or
authorization. Native untyped decoding is outside this contract.
