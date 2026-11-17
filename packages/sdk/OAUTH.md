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
  work after cancellation. Never expose store keys or values in logs. Records are
  `StoredRecord`s with a `kind`: a `binding` (non-secret discovery result under the
  binding key: namespace, backend, purpose, full endpoint), a `grant` (under the
  grant key: namespace, issuer, resource, client, flow and partition) and a
  `pending_login`. The allowed ceiling, secrets, token-endpoint auth method and
  scope sets are not identity: widening or narrowing the ceiling never orphans a
  grant. Default grants are isolated per binding; an explicit `grantPartition`
  shares consent only after each destination and purpose independently passes
  local approval. Preserve records verbatim; expiry is optional.

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
opens UI or creates a login: it throws `interaction_required` when login is needed.
Unknown endpoints are anonymous until challenged or explicitly prepared. Once a
binding is stored, the up-front lookup sends its stored token on the first
attempt, including for uploads and notifications that are never replayed. That
lookup never runs protected-resource discovery or creates a login. It renews an
unusable token (refresh, or client-credentials re-acquisition) with the binding's
persisted authorization-server metadata, fetching only the stored issuer's
metadata if that is missing (`discovery_failed` on failure). A known binding that
cannot be renewed, including one needing login (`interaction_required`), fails
the operation. It is anonymous only when no binding is stored or the host policy
refuses (`selectClient` throwing); other configuration errors propagate, and a
selection naming a different grant is `discovery_failed`. Full discovery runs only on a cache miss,
challenge handling, or a host `prepare` that must exchange or create a login; a
`prepare` with a usable cached token makes no metadata calls. Uploads use their
own bindings and isolated storage keys by default.

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

`PendingLogin` is a plain-data handle with an authorization URL and `expiresAt`.
Keep it private: the URL contains OAuth state. The login is a stored record, so
the handle may be serialized and completed or cancelled from any process sharing
the store. Its lifetime is fixed at creation by `loginLifetimeMs` (default and
maximum ten minutes), independent of the creating budget or its cancellation.
A later `prepare` reuses it when the grant key and redirect match and the new
requested plus required scopes are covered; otherwise it supersedes it. With the
same grant key and redirect, the new login requests old ∪ ((new requested ∪ new
required) ∩ new ceiling) and stores the union of both ceilings; otherwise it uses
only the new caller's scopes and ceiling. Because reuse requires the exact
redirect, hosts sharing a store must keep the redirect stable per grant key (or
give per-process ephemeral loopback redirects distinct grant partitions). A login ends by
completion (a claimed valid callback, including consent denial), supersede,
`cancel` or expiry; a callback for an ended login fails `interaction_required`.
Redirect, state and issuer are validated before the login is claimed, so a stray
callback cannot burn it. Completion reselects current host client authentication
outside store coordination before it claims the callback; secret rotation does
not require new consent. Records never contain client secrets.

For step-up, an `interaction_required` from a 403 `insufficient_scope` carries
`requiredScopes`; pass them back with `oauth.prepare(context, budget, { requiredScopes })`.
Required scopes outside the caller's ceiling fail `access_denied`.

For unattended use, return a `ClientConfig` with `flow: "client_credentials"`,
a locally resolved `clientSecret`, and permitted `scopes`. `prepare` returns
`ready` and never requests UI. Grants and refresh send the RFC 8707 `resource`
parameter. Tokens need bearer type and valid values; `expires_in` must be a
positive integer (or digit string). Absent expiry means the token remains usable
until rejected. An acquisition (PKCE consent or client credentials, including a
step-up for an existing grant) requests previously granted ∪ ((requested ∪
required) ∩ ceiling) and records `granted = response ∩ (previously granted ∪
acquisition ceiling)`, where the acquisition ceiling is the one stored on the
login or the client-credentials caller's. A refresh records `response ∩ previous
grant`. Extra scopes are ignored. At use,
effective scopes are the grant ∩ the current ceiling, and only explicit or
challenge requirements are mandatory. The ceiling governs what the SDK requests
and records; it does not constrain what an issued token can do.

## Rotation, rejection and failure

Refresh runs inside host coordination, reloads the latest generation, and uses
CAS for replacement; concurrent callers reuse the refreshed grant. Refresh uses
the persisted authorization-server metadata; `prepare` and challenge handling
rediscover outside store locks, falling back to it during an outage. If the token
endpoint provably did not process a renewal (DNS, TCP connect or TLS handshake
failure, or HTTP 404/410), the stored issuer's metadata is refetched once,
persisted if the issuer is unchanged, and the renewal retried once; a changed
issuer or failed refetch is `discovery_failed`, repaired by host `prepare`. Caller cancellation is honoured
only before a token request is sent (approximated as before `policyFetch` is
called; the caller still gets its abort promptly, but a stalled connect holds the
grant lock until the commit timeout); receiving the response and committing it run
under their own budget (`commitTimeoutMs`, default 30s), so a late cancellation or
slow store never loses a rotated refresh token. On a 401 the rejected token is
dropped before any discovery, so a discovery failure never leaves it to be resent.
Ambiguous failures after sending (timeouts, resets, 5xx, non-OAuth bodies) return
`provider_failed` with no refetch or immediate retry, so a refresh token is never
replayed.
Missing refresh-token rotation retains the previous refresh token. Transient
failures preserve stored credentials and advise retry. An invalid token response
is never dispatched and fails `provider_failed`: an initial exchange persists
nothing, while a refresh keeps a valid rotated refresh token. A definitive refresh
`invalid_grant` returns `refresh_rejected` and deletes the grant only if it still
holds the presented refresh token. Client credentials reacquire noninteractively.
A 401 marks the rejected token stale (unless a newer generation exists), even
with unknown or future expiry, and challenge handling renews it at once, so it is
never resent, including after unreplayed notifications and uploads.

Public failures are redacted `AuthError`s with safe codes/recovery and no raw
provider messages, token bodies or cause chains. `Ready.credential.token` is not
enumerable. Native cancellation (the caller's reason, or `TimeoutError` at the
deadline) is preserved. There is no anonymous/alternate-provider fallback after
configured authentication fails.

A Bearer `403 insufficient_scope` challenge permits step-up only within the
locally allowed ceiling, and only for the challenged operation: requirements are
never persisted. Without a challenge scope, supply explicit host-required scopes
or the challenge is denied. Hooks alone decides replay (see the README).
