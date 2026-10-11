# Draft API

This private, non-normative API follows the canonical
[working draft](../../../agent-hooks-protocol/spec/draft/index.md) and
[schema catalogue](../../../agent-hooks-protocol/schema/draft/manifest.json).
Generated models cover the full draft catalogue; runtime helpers are reference
slices, not a complete host adapter. Use `agenthooksprotocol/client` for the
canonical host API. The root `agenthooksprotocol` entrypoint retains general JSON
admission, NDJSON framing, operational errors, and independent runtime helpers;
it does not provide an alternate protocol event model or runner.

## Validation and wire identity

Import from `agenthooksprotocol/draft`:

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
validated `ContentUploadReceipt` (`{ref, size, sha256}`). `config` supplies `endpoint`, optional
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
or mismatched receipts fail; 202 and 204 do not confirm availability. The
returned opaque `ref` is used unchanged. A retry may allocate a different ref;
this is not reference-based idempotence or a durable-storage acknowledgement.
See the normative [upload binding](../../../agent-hooks-protocol/spec/draft/content-upload.md).

## Preparing content for publication

`prepareWireContent(items, options)` prepares normalized item views. Supply a
`selection` map with a `default`, an `authorized(item)` predicate, an
`upload(bytes)` callback returning `Promise<ContentUploadReceipt>`, `mode` (`intercept`
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
pending-state evaluator. These independent fixtures do not replace the canonical
client boundary API. Local supplier IDs used by those helpers
are bookkeeping, not protocol identity.

The canonical composition rules require staging the whole response before
publishing effects. Input merge is shallow, null is literal, and replacement
removes omitted keys. Changed effective operations invalidate stale candidates
and approvals. A candidate does not authorize execution or bypass later
subscribers, required approval, or managed policy. No effect is not permission
to run. Atomic acceptance protects pending state; it is not rollback of external
side effects. See [composition](../../../agent-hooks-protocol/spec/draft/base/composition.md).

### Upload receipts and event references

`uploadContent` and `ContentReceiver.upload` return a `ContentUploadReceipt`
(`{ ref, size, sha256 }`). Keep that receipt at the upload boundary: the helpers
check the returned length and lowercase SHA-256 digest against the exact bytes
sent. `attachments.response(receipt)` formats the HTTP 201 confirmation only
**after** storage consumes the verified upload stream to successful EOF.

Use `contentReference(receipt)` from `agenthooksprotocol/draft` to publish only
`{ ref: receipt.ref }` in a content item's `body` or a file-change `before`/`after`
reference. A successful body-selected item has no outer `size` or `sha256` either.
Metadata-only and gap items can still disclose those fields. A receipt is not an
event reference. Inline reference metadata is rejected.

Resolve references using receiver storage and authenticated scope, not event
length/hash claims. `ContentReceiver.read(scope, reference.ref)` uses both scope
and opaque reference and returns a defensive copy; the reference is not a URL or
an authorization grant.

## Consumer settlement

`agenthooksprotocol/client` returns one authoritative, decoded `event`, canonical
pending `state`, complete `acceptedResponses` in acceptance order, and structured
`diagnostics`. The residual `effects` list contains actions to enact,
distinct from receiver acceptance evidence. Receiver responses retain omitted
fields, envelope extras, injection delivery timing, and ordering. Invalid responses publish no effects or state; earlier accepted
responses remain available. Caller contracts retain separate arguments, result,
and provenance types without replacing schema-owned containers. Edits are enacted
from `event` and returns from `state.candidate`; they are not replayed from `effects`.
Caller-owned types are inferred only from supplied codecs; unbound slots are `unknown`.

Local attachment bytes belong to `Attachment`, created with `bytes`, `lazy`,
`stream`, or `file`. Attachments are explicit input owners, not raw stream bodies.
The returned canonical event selects metadata for local bodies; `content` holds
the effective local owners and must be closed separately. Observations finish
before a boundary returns. Their delivery evidence is identified by
`diagnostics[].phase === "observation"`.

Generic `Hooks.dispatch` intentionally accepts canonical occurrence-shaped input
for catalogue-driven harnesses. Named methods accept generated host facts and
perform schema-owned projection. Both return the same typed settlement and reject
malformed events or origin-incompatible state, including pre-cancelled calls.
Low-level generated structural codecs and canonical validators remain explicit
wire tooling; preserving unknown JSON fields does not grant effect or enum
semantics. JSON admission and NDJSON framing are independent transport utilities,
not alternate SDK event models.

`HooksOptions.auth` accepts the canonical `DeliveryAuthProvider` only. `auth()`
implements that contract and also supplies independent OAuth discovery, token
exchange, storage, and refresh helpers. The OAuth `Credential` includes lifecycle data;
`DeliveryCredential` carries the bearer token and optional provider-owned attempt
identity for one request. These are distinct responsibilities, not aliases.

Generic dispatch content parts require canonical `selection`; omission is not
silently decoded as a selected body. Named host inputs use the generated host
projection to create their canonical envelope and content selections.
