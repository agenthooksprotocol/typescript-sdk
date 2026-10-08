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
for canonical validation and reference boundary helpers.

See the [SDK documentation and examples](https://github.com/agenthooksprotocol/typescript-sdk#readme)
for all entrypoints and integration guidance. The testing and conformance
workspace packages are not published.

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

Migration: the query APIs are additive. Object-input parsing now rejects class
instances, sparse arrays, cycles, accessors, and non-JSON properties rather than
silently discarding them. Pass plain JSON data instead. Generated model aliases
remain static types; constructors/helpers do not claim runtime validation or
authorization. Native untyped decoding is outside this contract.
