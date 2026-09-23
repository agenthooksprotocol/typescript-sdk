# Agent Hooks Protocol SDK for TypeScript

TypeScript models, JSON codecs, and runtime utilities for the [Agent Hooks Protocol (AHP)](https://github.com/agenthooksprotocol/agent-hooks-protocol).

The generated schema API follows the current AHP `draft` snapshot. The root runtime provides the deny/no-effect `tool.before` interception flow over stdio; the draft entrypoint adds canonical validation and reference boundary helpers. Node.js 20 or newer is required.

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
