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

Discovered subscriptions are restricted to the host's supported event/mode pairs, including expansion of existing wildcard selectors. The SDK does not convert an intercept subscription to observation or rewrite content, timeout, or failure-policy settings. If discovery fails or no subscriptions remain, that backend is skipped; other backends retain their registration order. `initializationDiagnostics` records sanitized backend identifiers and skip codes after initialization. There is no required-hook negotiation or application policy gate.

Await `initialized` before checking interest for discovery-configured backends. Explicit-only registrations preserve synchronous interest checks. Boundary dispatch already waits for initialization.

Discovery does not change per-interception capabilities or authorize new effects. Transport URLs, credentials, and headers remain client configuration. Backend declarations do not provide a guarantee that the client will subscribe to every advertised event. Reinitializing the client is the supported mechanism for loading a new advertisement; there is no background refresh.

## Discovered uploads

A discovered `upload` is admitted like any other discovered setting: the backend is already trusted with the content it receives, and your configured backend headers apply to its uploads as they do to explicit ones.

The exception is local secrets. A discovered `upload.auth` naming `tokenEnv`, `tokenRef`, or `clientSecretRef` skips the entire backend with `CONFIGURATION_LOCAL_SECRET`, before anything is resolved, because only a registration may name them. Explicit local subscriptions may use them as before.
