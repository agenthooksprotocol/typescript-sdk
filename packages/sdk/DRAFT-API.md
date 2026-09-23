# Draft API

This private, non-normative API follows the canonical
[working draft](../../../agent-hooks-protocol/spec/draft/index.md) and
[schema catalogue](../../../agent-hooks-protocol/schema/draft/manifest.json).
Generated models cover the full draft catalogue; runtime helpers are reference
slices, not a complete host adapter. The root `@agenthooksprotocol/sdk` entrypoint
and `ToolBeforeRunner` remain a narrower deny/no-effect `tool.before` stdio runner.

## Validation and wire identity

Import from `@agenthooksprotocol/sdk/draft`:

- `parseInterceptRequest` and `parseInterceptResponse` accept JSON text.
- `validateInterceptRequest` and `validateInterceptResponse` accept unknown values.
- Each returns `{ok: true, value}` or `{ok: false, errors}`.
- `InterceptRequest`, `InterceptResponse`, `Effect`, `Capabilities`, and `JsonValue`
  provide generated types. `draftCodecs` exposes permissive generated codecs,
  **not authorization validators**.

The wire revision is `draft`. Requests carry the full event envelope in
`params.event`; the JSON-RPC request ID equals `params.event.id` and is reused on
retry. A response must correlate to its pending request. Schema validation does
not replace capability checks, authorization, or host policy.

Subscription IDs remain local to registration, dispatch, and bookkeeping. They
must not be serialized as wire identity, including in candidate provenance,
request envelopes, content descriptors, or upload headers. Upload authorization
comes from receiver-validated credentials and their authorized scope, not from a
caller-supplied subscription ID or reference.

## Binary content upload

`uploadContent(config, bytes, options)` accepts a `Uint8Array` and resolves to a
validated `{ref, size, sha256}` descriptor. `config` supplies `endpoint`, optional
`timeoutMs` and `maxBytes`, and optional bearer `auth: {type: 'bearer', tokenEnv}`.
Use `options.resolveToken` to resolve that upload credential. Event credentials
are not inherited. `options.allowLoopback` permits HTTP only for explicit
loopback tests; ordinary endpoints require HTTPS.

The helper snapshots the bytes and POSTs raw octets to the exact configured
endpoint, with `Content-Type: application/octet-stream`, exact `Content-Length`,
and `AHP-Content-SHA256`. It rejects redirects. The sender supplies neither a
content reference nor subscription identity.

Only HTTP **201 Created** with `Content-Type: application/json` and a valid
receiver-allocated `{ref, size, sha256}` response confirms upload. The returned
size and lowercase SHA-256 must match the exact bytes sent. Missing, malformed,
or mismatched descriptors fail; 202 and 204 do not confirm availability. The
returned opaque `ref` is used unchanged. A retry may allocate a different ref;
this is not reference-based idempotence or a durable-storage acknowledgement.
See the normative [upload binding](../../../agent-hooks-protocol/spec/draft/content-upload.md).

## Preparing content for publication

`prepareWireContent(items, options)` prepares normalized item views. Supply a
`selection` map with a `default`, an `authorized(item)` predicate, an
`upload(bytes)` callback returning `Promise<BodyReference>`, `mode` (`intercept`
or `observe`), and `failClosed`. Optional `timeoutMs` and `maxBytes` bound transfer.
For example, the callback can be:

```ts
upload: (bytes) => uploadContent(config, bytes, { resolveToken })
```

The helper does not upload metadata-only, omitted, or unauthorized bodies. It
snapshots selected bytes and validates the callback's descriptor against their
exact size and SHA-256 before exposing `body`. Failure produces an explicit gap;
fail-closed interception throws instead. Observation preparation cannot gate
execution or reopen settlement. Complete uploads before publishing any referring
event; never replace a failed upload with inline bytes, a local path, or a URL.

The current helper selects using `category`, falling back to `kind`, then
`selection.default`. Producers must apply the canonical category rules (including
reasoning precedence), provide required model-visible roles, keep child roles
consistent with their owners, and project opaque/native payloads so they do not
bypass content permissions. The helper is not a complete semantic validator.

## Runtime boundaries

`stageResponse`, `decide`, and `PendingState` expose a synthetic `tool.before`
pending-state evaluator. Other exported boundary helpers do not turn the root
runner into a full-catalogue adapter. Local supplier IDs used by those helpers
are bookkeeping, not protocol identity.

The canonical composition rules require staging the whole response before
publishing effects. Input merge is shallow, null is literal, and replacement
removes omitted keys. Changed effective operations invalidate stale candidates
and approvals. A candidate does not authorize execution or bypass later
subscribers, required approval, or managed policy. No effect is not permission
to run. Atomic acceptance protects pending state; it is not rollback of external
side effects. See [composition](../../../agent-hooks-protocol/spec/draft/base/composition.md).
