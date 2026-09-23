# TypeScript interoperability adapters

These are test-only adapters, not production agent-host integrations. Their wire
contract is the canonical sibling protocol repository:

- [`spec/draft`](../../agent-hooks-protocol/spec/draft/index.md)
- [`schema/draft`](../../agent-hooks-protocol/schema/draft/)
- [`interop/CONTRACT.md`](../../agent-hooks-protocol/interop/CONTRACT.md)

Build the SDK before running an adapter or its tests:

```sh
pnpm build
node --test interop/*.test.mjs
node interop/server.mjs --config /absolute/server-config.json
node interop/client.mjs --config /absolute/client-config.json
```

`adapter.json` lists the core and lifecycle entry points. `cross-stdio.py` runs
the shared corpus in both TypeScript/Rust directions when the sibling Rust SDK
and its toolchain are available. External matrix runners require their own
language toolchains and protocol-owned fixtures.

## Protocol and local control

Core HTTP delivery uses POST `/intercept`; stdio uses canonical JSON-RPC NDJSON.
Stdio discovery uses `hooks/capabilities` with `params.protocolVersion: "draft"`
and a correlated `result.manifest`. The core test binding also exposes an
authenticated GET `/capabilities` returning its capability object. Discovery does
not start a session or execute tools. Generated codecs and canonical schemas
validate protocol messages; runtime checks enforce cross-field and state rules.

The separate loopback control listener exposes `/health`, `/receipts`, `/release`,
and `/shutdown`. Control operations, barriers, readiness files, scenario labels,
and report fields are local test orchestration, not AHP wire extensions. Readiness
and reports are written by atomic rename. Watchdogs bound waits and child cleanup.
See [LIFECYCLE.md](LIFECYCLE.md) for lifecycle and catalogue operation.

## Authentication and content

HTTP supports no authentication, bearer tokens, test OAuth acquisition, signed
workload assertions, and mutual TLS. Stdio trusts the launched process; HTTP auth
modes are inapplicable there. OAuth/workload verification uses **test-only** HS256
trust, including issuer, audience, purpose, and expiry checks. OAuth redirects
are rejected rather than forwarding client secrets. Duplicate Authorization
fields are rejected. TLS health counters distinguish sanitized certificate
verification failures from other handshake failures.

An upload has independent credentials. Event tokens, client certificates, and
OAuth acquisition are never inherited by upload requests. Upload routing and
reference access use an authenticated receiver scope, never JSON-RPC IDs or
fields asserted in an event. An explicitly configured anonymous upload policy
is also possible for loopback tests.

Uploads POST exact binary bytes with `Content-Type: application/octet-stream`,
`Content-Length`, and `AHP-Content-SHA256`. The receiver validates framing, length,
hash, and authorization, allocates an immutable opaque reference, and returns
**201** with JSON `{ref,size,sha256}`. The sender validates the descriptor and
checks length/hash against the exact sent bytes before publishing the returned
reference. Retries may allocate different references; changed bytes require a
new upload. Redirects, 202, 204, missing descriptors, and integrity mismatches
never confirm availability. No caller-selected reference or subscription
identity is transmitted in upload headers or protocol messages.

Core fixture `subscriptions` select local content policy; `row.subscription`
selects a policy when more than one is configured. Local `contentBodies[].ref`
labels identify fixture bytes only and are replaced by confirmed receiver refs.
`uploadSubscriptions` maps receiver policies to upload credentials and a `scope`;
`contentScope` is the event endpoint's trusted receiver scope. Policy keys and
scope names are not transmitted. The event endpoint authenticates first, then
resolves each descriptor in that configured scope.

## Validation and limits

Unknown configuration, capability, authentication, upload, and control metadata
fields are accepted while recognized fields remain validated. Unknown effects
and unsupported operations are rejected atomically: partial input, message,
permission, candidate, or scheduling changes are not published. Capability
selection is not authorization. Observations contain permission-filtered,
accepted effective event content, without local subscription identity or a
separate decision summary. Their returned effects never affect execution.

The harness simulates execution decisions; it does not execute real tools or a
model loop. It provides no durable upload service, observation delivery guarantee,
production federation, or managed enforcement. Only implemented coverage is
advertised. Negative tests cover authentication, duplicate credentials, redirects,
upload isolation/integrity, cancellation, unsolicited replies, unsupported effects,
and atomic state application.
