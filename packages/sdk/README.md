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
