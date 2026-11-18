# Shared subscription configuration

Clients and backends use the same subscription declarations. The backend advertises defaults; explicit client subscriptions replace those defaults completely.

```ts
import {
  content,
  duration,
  events,
  subscription,
  type Configuration,
} from "agenthooksprotocol";
import { hooks, type ServerHandlers } from "agenthooksprotocol/server";

const configuration = {
  subscriptions: [
    subscription.intercept({
      events: [events.toolBefore],
      timeout: duration.milliseconds(750),
      failurePolicy: "fail-open",
      content: content.metadata(),
    }),
    subscription.observe({
      events: [events.toolAfter],
      content: content.metadata(),
    }),
  ],
} satisfies Configuration;

const backend = {
  configuration,
  intercept: { toolBefore: async () => ({}) },
  observe: { toolAfter: async () => {} },
} satisfies ServerHandlers;

// Use in the application's authenticated HTTP route:
// return hooks.handle(request, backend);
// The same backend declaration works with serveStdio(backend).
```

The SDK serves `hooks/configuration` without invoking event handlers or creating a session. It snapshots a static declaration when configuration discovery first uses it. Applications own authentication and routing. Omitting `configuration` leaves discovery unsupported; a configuration-only backend may serve discovery independently of event callbacks.

## Dynamic configuration handlers

The same `configuration` field also accepts a synchronous or asynchronous handler. The SDK invokes it for each valid `hooks/configuration` request, validates and detaches its return value, and constructs the correlated response. Static declarations continue to work unchanged.

```ts
import type {
  ConfigurationContext,
  ServerHandlers,
} from "agenthooksprotocol/server";

// The application authenticates the HTTP request before calling hooks.handle.
// Capture the verified tenant in the route's closure, not in protocol metadata.
const backend = {
  configuration: async ({ request, signal }: ConfigurationContext) => {
    signal.throwIfAborted();
    return loadTenantConfiguration(authenticatedTenant, {
      signal,
      requestId: request.id,
    });
  },
  intercept: { toolBefore: async () => ({}) },
} satisfies ServerHandlers;
```

`loadTenantConfiguration` and `authenticatedTenant` above are application-owned. The context contains only the validated JSON-RPC `request` and the current `AbortSignal`; request IDs and metadata are not authenticated identity. The same handler works with `serveStdio`, where process authentication remains the application's responsibility.

Dynamic results are not cached. Mutating a returned object cannot change a response already prepared by the SDK. The SDK preserves request correlation even if the callback mutates its context's request copy. Missing configuration remains a method-not-found response; returning `undefined`, `null`, or invalid configuration is a sanitized backend error, not an opt-out. Callback exceptions and rejections never expose application error messages.

Malformed requests and unsupported protocol versions do not invoke the handler. Configuration callbacks do not run for ordinary event delivery and do not create sessions or grant effects. Cancellation is passed through the context and stops waiting for the callback; handlers should honor the signal to cancel their own I/O. An already-aborted discovery does not invoke a dynamic handler. Existing static snapshot behavior is unchanged.

## Client initialization

```ts
import { Hooks } from "agenthooksprotocol/client";

const client = new Hooks({
  protocolVersion: "draft",
  hooks: [{
    id: "com.example.policy",
    transport: { type: "http", url: "https://policy.example/hooks" },
    authentication: { type: "bearer", tokenEnv: "POLICY_TOKEN" },
    // No subscriptions: fetch defaults during initialization.
  }],
}, {
  source: "urn:example:harness",
  harness: { name: "example", version: "1" },
  capabilities: { toolBefore: { intercept: { deny: true } } },
  configurationTimeoutMs: 5000,
});

await client.initialized;
const interested = client.subscribes(events.toolBefore);
// ... use client boundaries ...
await client.close();
```

For explicit client configuration, add `...configuration` to the backend registration. No discovery request is made in that case. JSON files use the same canonical subscription representation: `mode`, event strings, `timeoutMs`, `failurePolicy`, and `content`. Helpers serialize to those fields; they do not introduce a second wire format.

An explicit empty `subscriptions` array remains invalid and never enables discovery. Missing subscriptions enable discovery over the configured HTTP or stdio transport. Discovery uses the backend's existing event credentials and configured HTTP headers, with a separate bounded initialization budget (5 seconds by default). Closing the client cancels initialization and retires owned transports.

Discovered subscriptions are restricted to the host's supported event/mode pairs, including expansion of existing wildcard selectors. The SDK does not convert an intercept subscription to observation or rewrite content, timeout, or failure-policy settings. If discovery fails or no subscriptions remain, that backend is skipped; other backends retain their registration order. There is no required-hook negotiation or application policy gate.

Each skip appends `{ backendId, code, authError?, recovery?, requiredScopes? }` to `initializationDiagnostics`, with one of the protocol's codes:

| Code | Cause | Re-attempted |
| --- | --- | --- |
| `configuration_unavailable` | Transport failure, timeout, an HTTP status other than 200 (401/403 also carry the auth code), a JSON-RPC error other than method-not-found, or endpoint authentication failure | Yes |
| `configuration_invalid` | A 200 response that is method-not-found, uncorrelated, malformed or version-incompatible, or a transport that local configuration cannot build | No |
| `no_applicable_subscriptions` | A valid advertisement with no supported subscriptions | No |
| `configuration_local_secret` | A discovered upload naming a local secret reference | No |

On stdio, a frame answering another request id is discarded, so a backend that never answers correctly times out as `configuration_unavailable`. When authentication caused the failure, `authError` is the safe `AuthError` code, `recovery` its paired recovery and `requiredScopes` any validated required scopes. Diagnostics never contain credentials, response bodies or event content. Cancellation (closing the client) rejects `initialized` and emits no diagnostic.

A `configuration_unavailable` backend is re-attempted at a later event admission:

- after a successful host `prepare` (or completed login) for that backend's event endpoint, at once. The auth provider reports these through its optional `onPrepared` subscription, which `managedOAuth(...).provider(...)` and `auth.compose(...)` implement; and
- when there is no `auth`, or its `recovery` is `retry`, after a backoff of 30 seconds that doubles after each failed attempt up to 1 hour. Set `configurationRetry: { initialDelayMs, maxDelayMs }` to change it. A `login`, `configure` or `none` recovery is never re-attempted on backoff.

A due re-attempt starts at an event admission and runs in the background, as one shared operation on its own discovery budget. No dispatch waits for it: the admitting event and concurrent ones use the routes current at their admission, so a hung discovery never delays delivery to other backends. A successful re-attempt installs its routes in one step for later events, so no caller sees a partial route set, and earlier events are not replayed. Initialization is different: dispatch still waits for `initialized`, because the protocol resolves configuration before admitting any event. A backend with omitted subscriptions has no failure policy while its configuration is unavailable; enforcing delivery requires explicit `fail-closed` subscriptions.

Await `initialized` before checking interest for discovery-configured backends. Explicit-only registrations preserve synchronous interest checks. Boundary dispatch already waits for initialization.

Discovery does not change per-interception capabilities or authorize new effects. Transport URLs, credentials, and headers remain client configuration. Backend declarations do not provide a guarantee that the client will subscribe to every advertised event. Reinitializing the client is the supported mechanism for loading a new advertisement; apart from the re-attempts above there is no background refresh.

## Discovered uploads

A discovered `upload` is admitted like any other discovered setting: the backend is already trusted with the content it receives, and your configured backend headers apply to its uploads as they do to explicit ones.

The exception is local secrets. A discovered `upload.auth` naming `tokenEnv`, `tokenRef`, or `clientSecretRef` skips the entire backend with `configuration_local_secret`, before anything is resolved, because only a registration may name them. Explicit local subscriptions may use them as before.
