# Lifecycle and catalogue test binding

`lifecycle-client.mjs` and `lifecycle-server.mjs` exercise real canonical messages
while the separate loopback control channel schedules deterministic test steps.
They use the same build prerequisites and security boundaries as [README.md](README.md).

## Configuration and execution

Both entry points accept `--config /absolute/config.json`. Shared configuration
includes `transport` (`http` or `stdio`), `scenarioFile`, and `auth`. The server
writes `readinessFile` with `endpoint`, `controlEndpoint`, `uploadEndpoint`, and
`pid`. The client writes `reportFile`. For stdio, configure `serverCommand`,
`serverCwd`, and optional `serverConfig`; the client owns and terminates its child.

```sh
node --test interop/lifecycle.test.mjs interop/wire-integration.test.mjs
node --test interop/catalogue.test.mjs interop/settlement.test.mjs
```

Fixtures contain canonical `requests`/`responses` plus local scheduling `steps`.
The local operations include send, wait, release, receive, accept, cancel,
fail-open, upload, observe, and controlled unsolicited emission. Unsupported
operations fail rather than silently changing state. These operations and report
fields are not AHP methods or envelope fields.

## Settlement and observations

A response must match its pending request ID. Acquisition is distinct from
acceptance; only acceptance publishes effects. Duplicate, late, cancelled, or
unsolicited responses cannot reopen a settled decision. A serial chain passes
accepted effective state to its next interceptor. On a short circuit, remaining
uncalled interceptors receive only best-effort observations; called interceptors
receive no automatic second copy. Explicit observers remain independent.

Local subscription labels select policy and observation callbacks, never wire
identity or authorization. Notifications carry `protocolVersion` and `event`,
with no request ID. Projected content includes only accepted effective state and
the observer's permitted content. Observers cannot return effects. Their processing
and failed uploads do not delay interruption or reopen settlement. The test runner
may drain observer receipts after settlement to collect evidence; that is not a
production delivery guarantee.

## Upload configuration

The client merges the default loopback upload endpoint with `upload`, an optional
local `uploadPolicies[step.subscription]`, and optional `step.upload` overrides.
`step.ref` is a fixture-only alias. Confirmed descriptors replace these aliases
before dispatch; ambiguous aliases fail instead of selecting another policy.

Receiver `uploadSubscriptions` entries specify `auth: {type:"bearer",tokenEnv}`
or explicit `anonymous:true`, a local `scope`, and optional `authorized:false`
for authenticated-but-forbidden test principals. A single matching credential
policy selects the scope; ambiguous or unmatched policies fail. Alternatively,
`uploadAuth: {token,scope}` supplies one test upload credential. `contentScope`
selects the scope available to the authenticated event endpoint (default
`"default"`). Neither event IDs nor JSON-RPC IDs select scope.

The separate compaction and elicitation fixtures use
`AHP_COMPACTION_UPLOAD_TOKEN` and `AHP_ELICITATION_UPLOAD_TOKEN`, respectively;
their event credentials are separate. Elicitation sender plans provide
`uploadToken` or an explicit upload-step Authorization header. Upload confirmations
are validated before their returned references can be used.

## Catalogue suite

Set `suite:"catalogue"` to discover `catalogueManifest`, evaluate registration
against it, and exchange typed observations. The manifest advertises only its
implemented events, modes, and controls; it does not assert authenticated identity
or production managed enforcement. Registration requires actual credential
resolution and supported event/mode combinations.

Lineage uses `(source,event.id)` and `parentEventId`, independently of transport
request IDs. It checks cycles, incompatible before/after identities, and claimed
updates without changes. An event's asserted source is correlation metadata,
not an authentication claim. Receipts retain canonical incoming envelopes and
sanitized outcomes, never HTTP credentials.
