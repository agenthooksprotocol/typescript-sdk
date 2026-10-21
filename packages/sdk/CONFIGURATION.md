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

The SDK serves `hooks/configuration` without invoking event handlers or creating a session. It snapshots the declaration when configuration discovery first uses it. Applications own authentication and routing. Omitting `configuration` leaves discovery unsupported; a configuration-only backend may serve discovery independently of event callbacks.

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
