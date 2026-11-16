# Managed OAuth for Agent Hooks Protocol

`agenthooksprotocol/oauth` is an opt-in code-loading subpath of the SDK. Install
only `agenthooksprotocol`; its regular dependencies include `oauth4webapi`, even
when your application does not import the OAuth subpath.
The existing SDK OAuth exports remain supported; this adapter adds coordinated
storage and an explicit host-driven login lifecycle without changing the wire.

## Required host capabilities

There is deliberately no default fetch, store, browser, listener or refresh worker.
Supply all of these capabilities:

- `policyFetch(url, init, { purpose, operation })`: enforce HTTPS certificate
  validation and destination/DNS/connect policy on the actual connection. Pin or
  otherwise verify resolved addresses against that policy to prevent DNS rebinding.
  Honor `init.signal` and `redirect: "error"`; never follow or forward credentials
  across redirects. Do not use a URL-only allowlist with an unchecked connector.
- `checkDestination(url, purpose, operation)`: authorize each metadata/token
  destination and the final authorization URL before UI handoff. DNS/connection
  enforcement still belongs to `policyFetch`; UI/callback transport must enforce
  equivalent destination policy when opening an authorization URL.
- `selectClient(issuers, resource, context, operation)`: select a locally trusted
  issuer, client identity, flow and permitted scopes. Advertisements never create
  trust. Resolve client secrets in host infrastructure, honor cancellation, and
  do not log the resulting client configuration.
- `store`: implement `load`, atomic generation-aware `compareAndSet`, and
  `coordinate(key, signal, work)`. Coordination must serialize the full callback
  across all instances sharing the store (including processes where applicable).
  Waiting and storage operations must honor cancellation; do not invoke queued
  work after cancellation. Never expose store keys or values in logs. Keys include
  namespace, backend, purpose and full endpoint in the binding key. Grant keys
  additionally include trusted issuer, resource, client, flow and the locally
  allowed scope ceiling. Keep namespaces stable and separate tenants. Secrets,
  metadata and granted/requested scopes are not grant identity. Default grants
  are isolated per binding; an explicit `grantPartition` shares consent only
  after each destination and purpose independently passes local approval.
  Preserve the complete `StoredCredential` record, including non-secret
  `bindingMetadata` entries under the binding keyspace and rejection/quarantine
  flags. Binding metadata records are not bearer credentials. Expiry is optional;
  do not require an `expiresAt` field in the store serializer.

The adapter rejects redirects, URL credentials, non-HTTPS network endpoints,
resource/issuer mismatches and broader-than-permitted scopes. It does not register
clients dynamically. Unsigned JSON metadata is supported over trusted HTTPS;
signed metadata is rejected until a verified signed-metadata integration exists.
Client credentials require explicit advertised grant support; PKCE requires S256.
Authorization-server discovery removes a terminating issuer slash only for
well-known lookup paths; the metadata issuer must still match the original issuer
exactly. Resource path discovery preserves endpoint queries and requires the
returned resource identifier to match that discovery source exactly. Origin-root
fallback remains bound to the origin, not the original endpoint query.

## Compose without replacing bearer resolution

```ts
import { auth, AuthError } from "agenthooksprotocol/client";
import { managedOAuth } from "agenthooksprotocol/oauth";

const oauth = managedOAuth({
  namespace: "tenant-a/desktop",
  store: host.atomicTokenStore,
  policyFetch: host.oauthFetch,
  checkDestination: (url, purpose, operation) =>
    host.authorizeDestination(url, purpose, operation),
  selectClient: (issuers, resource, context, operation) => {
    operation.signal.throwIfAborted();
    const client = host.trustedClientFor(context.backendId, resource);
    if (!client || !issuers.includes(client.issuer)) throw new AuthError("access_denied");
    return client;
  },
});
const route = oauth.provider({ budget: context => host.remainingBudget(context.signal) });
const provider = auth.compose({
  bearer: auth.bearer({ resolveCredentialReference: host.resolveSecret }),
  oauth: route,
  discover: route,
});
```

`host` is application-owned infrastructure, not an exported SDK implementation.
Its budget returns `{ signal, deadline }`, with an absolute Unix-millisecond
deadline that does not extend the enclosing delivery. Provider integration never
opens UI: it throws `interaction_required` when login is needed. Hooks keeps its
existing bounded, protocol-safe retry rules and explicit Authorization precedence.
Unknown endpoints remain anonymous until challenged or explicitly prepared.
After a trusted binding is stored, cached credentials are sent up front, including
for uploads and notifications that cannot be replayed. Uploads use their own
bindings and isolated storage keys by default.

## Host-driven PKCE

```ts
const budget = { signal: controller.signal, deadline: Date.now() + 120_000 };
const result = await oauth.prepare(deliveryContext, budget);
if (result.type === "pending_login") {
  // The host chooses whether/how to show UI and receive the complete callback URL.
  const callback = await host.receiveCallback(result.authorizationUrl, budget);
  const ready = await oauth.complete(result, callback, budget);
  // Use ready.credential only with the original destination and binding.
}
```

`PendingLogin` is a frozen opaque handle with an authorization URL and `expiresAt`.
Keep it private: the URL contains OAuth state. The host can call
`oauth.cancel(pending, budget)` to discard it. Pending state is in-memory per
adapter instance and is not restart-persistent; keep that instance alive through
completion. Preparation deduplicates live pending logins per identity in that
instance only when requested/required scopes, redirect and consent budget are
compatible. Replacing an incompatible pending operation invalidates its old
handle. Reuse the same consent budget when polling an eligible operation.
Callbacks are single-use, validate state/issuer/redirect binding through
the library, and cannot outlive the original budget or ten minutes. Completion
has its own cancellable budget, capped by that original deadline. Tokens are
written only under the original CAS generation, so another completed login cannot
be overwritten. Completion reselects current host client authentication outside store coordination
before it claims the callback. Secret rotation does not require new consent;
principal, redirect, requested scopes and explicit host requirements must remain
compatible with the pending operation. Pending records do not retain client
secrets. Completion also checks the current generation before sending the code,
so a stale pending login cannot consume a code after another login has replaced
its credential. Cancellation releases retained login secrets immediately; expired
records are pruned on the next prepare call, with expiry enforced on every use.
After abandoned/expired login, prepare again; no worker cleans up in the background.

For unattended use, return a `ClientConfig` with `flow: "client_credentials"`,
a locally resolved `clientSecret`, and permitted `scopes`. `prepare` returns
`ready` after the library exchange and never requests UI. Both grants and refresh
send the RFC 8707 `resource` parameter. Tokens need bearer type and valid values. Absent expiry means the token remains
usable until rejected; positive expiry is enforced when provided. Requested
scopes, the locally allowed ceiling and explicit operation requirements are
distinct: servers may narrow requested scopes or grant additional locally
allowed scopes. A token must satisfy the explicit requirements of its operation.

## Rotation, rejection and failure

Refresh runs inside host coordination, reloads the latest generation, and uses
CAS for replacement. Concurrent callers reuse the refreshed generation. Missing
refresh-token rotation retains the previous refresh token. Transient failures
preserve stored credentials and return retry advice. An ambiguous rotating
refresh cannot be rolled back at the authorization server: retry can subsequently
receive `invalid_grant`. A refresh response that broadens the prior grant is
quarantined: its rotated refresh material is retained, but the access token is
not usable and a fresh grant is needed. Definitive PKCE refresh `invalid_grant` reports
`refresh_rejected` and requires fresh login. Client credentials reacquire
noninteractively and never request human login. A stale 401 cannot invalidate a newer
generation. Challenge never independently replays HTTP requests.

Public failures are redacted `AuthError`s with safe codes/recovery and no raw
provider messages, token bodies or cause chains. Native cancellation (including
the caller's reason) is preserved. Budgets stop waiting, but cannot undo a host
connector/store that violates its cancellation contract; no store or network
adapter should detach work. There is no automatic anonymous/alternate-provider
fallback after configured authentication fails.

A Bearer `403 insufficient_scope` challenge permits step-up only within the
locally allowed ceiling. Without a challenge scope, supply explicit host-required
scopes or treat the challenge as denied; the SDK does not invent permissions. PKCE returns login advice for a subsequent host-owned
`prepare`; dispatch never creates consent state or borrows the delivery budget
for login. Client credentials can acquire the permitted scopes automatically.
Only the transport may perform its existing single safe retry: authentication
never replays effectful deliveries, notifications or uploads.
