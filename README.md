# Private TypeScript AHP reference slice

This workspace is a **private, non-normative reference implementation** of the Agent Hooks Protocol (AHP) v0.1 `tool.before` stdio slice. It is not a released SDK or the protocol specification. **Before any release, every protocol type and runtime validator here must be reconciled with the canonical AHP schema.** All workspace packages are marked `private`.

## Scope

- JSON-RPC 2.0 method `hooks/intercept` with params `{ protocolVersion: "0.1", event, capabilities: { effects: ["deny"] } }`.
- The canonical event shape is `{ id, source, type: "tool.before", time, session, tool, native?, extensions? }`. Session contains `id` and optional `cwd`, `workspaceRoots`, `model`, and `agent`. Tool contains `callId`, `name`, the Working Draft `kind` taxonomy (`shell`, `file_read`, `file_write`, `file_edit`, `search`, `fetch`, `task`, `mcp`, or `other`), object-valued `input`, and optional `mcp`. IDs and the RFC 3339 event time are stable across retries.
- A successful result has `protocolVersion: "0.1"` and either `effects: []` or one `{ type: "deny", reason, code?, extensions? }` effect. Deny reasons are non-empty; optional codes and extension keys use reverse-DNS names. Unknown fields are ignored, while unknown event types, effect types, and enum values are rejected.
- UTF-8 NDJSON over child-process stdin/stdout. Commands and argument arrays are passed directly to `spawn` with `shell: false`.
- `per_event` and `persistent` stdio `lifecycle` values. Persistent exchanges are serialized and a process is discarded after any operational failure.
- Registration-order composition is serial. A denial or fail-closed operational failure short-circuits later hooks. A successful no-effect chain returns `continue`, not `allow`: it does not grant authorization or bypass host controls.
- Each backend must explicitly select a `failurePolicy` of `fail-open` or `fail-closed`. Bounded retries reuse the exact serialized request, including every ID. A timeout starts before process acquisition/spawn and covers writing, framing, and receiving the complete response.

Malformed JSON or JSON-RPC, invalid UTF-8/framing, timeout (including late output), process I/O failure, response-ID mismatch, JSON-RPC errors, incompatible versions, unsupported effects, and multiple effects are operational failures.

There is intentionally **no HTTP transport**.

## Packages

- `@agenthooksprotocol/sdk`: strict runtime types, validation, stdio transport, and `ToolBeforeRunner`.
- `@agenthooksprotocol/testing`: controllable `ahp-fake-backend` CLI. Its modes include `no-effect`, `deny`, `timeout`, `malformed-json`, `json-rpc-error`, `incompatible-version`, `unsupported-effect`, `multiple-effects`, `id-mismatch`, `malformed-deny`, and `unknown-fields`. Options can delay or byte-chunk output and record requests.
- `@agenthooksprotocol/conformance`: black-box runner and `ahp-conformance` CLI for a target command. A target is always represented as a command plus argument array; no shell command string is evaluated.

## Development

Node 20 or newer and pnpm are required. This dependency-free slice uses the installed TypeScript compiler.

```sh
pnpm install --offline --ignore-scripts
pnpm check
node packages/conformance/dist/src/cli.js -- node packages/testing/dist/src/fake-backend.js --mode no-effect
```

The conformance runner checks valid Unicode framing and repeat exchanges over persistent stdio. It is a focused reference-slice runner, not certification for the complete AHP protocol.
