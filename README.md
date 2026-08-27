# Agent Hooks Protocol SDK for TypeScript

TypeScript models, JSON codecs, and runtime utilities for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The generated schema API follows the current AHP `draft` snapshot. The runtime currently provides the `tool.before` interception flow over stdio. Node.js 20 or newer is required.

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

## Run a `tool.before` hook

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

## Packages

- `@agenthooksprotocol/sdk` — hook runner, stdio transport, runtime types, and operational errors
- `@agenthooksprotocol/sdk/generated` — schema-derived models and structural codecs
- `@agenthooksprotocol/testing` — configurable fake backend for integration tests
- `@agenthooksprotocol/conformance` — black-box conformance runner and CLI

## Development

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

## License

Apache-2.0
