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
  binding key: namespace, backend, purpose, full endpoint) and a `grant` (under the
  grant key: namespace, issuer, resource, client identity, flow and partition).
  The client identity is the configured client source (`preregistered:<id>`,
  `cimd:<url>` or `dcr`), never an issued client_id. Client-credentials DCR adds
  `registration` and `registration_failure` records; persisted pending logins
  add `pending_login` and `pending_index`. The allowed ceiling, secrets, token-endpoint auth method and
  scope sets are not identity: widening or narrowing the ceiling never orphans a
  grant. Default grants are isolated per binding; an explicit `grantPartition`
  shares consent only after each destination and purpose independently passes
  local approval. Preserve records verbatim; expiry is optional.

The adapter rejects redirects, URL credentials, non-HTTPS network endpoints,
resource/issuer mismatches and broader-than-permitted scopes. Clients come from
[client registration](#client-registration). Unsigned JSON metadata is supported over trusted HTTPS;
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
or when challenge handling or a host `prepare` must exchange or create a login; a
`prepare` with a usable cached token makes no metadata calls. An outcome that needs
no authorization-server request is returned without one: challenge handling that
ends in `interaction_required` makes none, and a pre-registered PKCE client on an
unknown target fetches only its protected-resource metadata (learning the binding,
without the issuer's metadata) before reporting that a login is needed. Uploads use their
own bindings and isolated storage keys by default.

## Host-driven PKCE

```ts
const budget = { signal: controller.signal, deadline: Date.now() + 120_000 };
const result = await oauth.prepare(deliveryContext, budget);
if (result.type === "pending_login") {
  // The host chooses whether/how to show UI and receive the complete callback URL.
  const callback = await host.receiveCallback(result.authorizationUrl, budget);
  const ready = await oauth.complete(callback, budget);
  // Use ready.credential only with the original destination and binding.
}
```

As in MCP clients, each login may use its own redirect: pass
`prepare(context, budget, { redirectUri })`, for example a loopback listener
bound to `127.0.0.1:0` for that login (otherwise `ClientConfig.redirectUri` is
used). HTTP redirects must use a literal loopback IP (`127.0.0.1` or `[::1]`);
`localhost` is `invalid_configuration` (RFC 8252 §8.3). The authorization, DCR
and token requests use the login's exact redirect, including its port.

`PendingLogin` is a plain-data handle with an authorization URL, `expiresAt` and
`state`. Keep it private: the URL contains OAuth state. `complete(callback,
budget)` finds the login by the callback's `state`. By default the login belongs
to the instance that created it, which receives its callback. With
`persistPendingLogins: true` it is stored instead, so another process sharing the
store can complete it from a pasted callback URL; the PKCE verifier is then held
only in that pending record. Its lifetime is fixed at creation by
`loginLifetimeMs` (default and maximum ten minutes), independent of the creating
budget or its cancellation; expired logins are deleted. Several logins may be
pending for one grant key, up to `maxPendingLogins` (default 5) per instance, or
per store when persisted; a new one beyond the cap cancels the oldest. Each
completion replaces the grant, so the newest completed login wins. A login ends by
completion (a claimed valid callback, including consent denial), `cancel`
(including by the cap) or expiry; a callback for an ended login fails
`interaction_required`. The login is looked up by the callback's `state` before
any host callback runs. The callback is then validated before the login is
claimed, so a stray callback cannot burn it: the exact redirect (including its own
query; parameters the authorization server adds, such as `session_state`, are
allowed), exactly one `state`, no `iss` other than the issuer, no fragment or
userinfo, exactly one of `code` or `error`, and no duplicated parameter; an invalid
or unparseable callback fails `access_denied` and leaves the login pending. A host callback or policy failure before the claim (for example
`selectClient` reselecting client authentication) keeps its own code, carries
no scopes and leaves the login pending (`loginEnded: false`), so the same
callback can complete it once the host recovers. After the claim, a token-endpoint `invalid_grant` fails
`interaction_required`; `invalid_client` fails `credential_unavailable` for a
pre-registered client, `invalid_configuration` for a CIMD client and
`interaction_required` for a DCR client (the next `prepare` registers again);
every other token-endpoint error (including `unauthorized_client`, `access_denied`
and `invalid_scope`), an unreachable or 404 endpoint, or an invalid token response
fails `provider_failed`. These errors carry no scopes, and the login is consumed.
`complete()` takes no pending-login handle: the callback's `state` names the login. Completion reselects current host
client authentication outside store coordination before it claims the callback;
secret rotation does not require new consent. Records never contain client secrets.

One decision procedure (`decide`, scope contract v2) serves every entry point:
`prepare`, `credential` (the up-front lookup and delivery, including preset
bindings), `challenge`, and the built-in `auth()` provider. Its inputs are the
requested scopes S (`ClientConfig.scopes`), the ceiling C (`allowedScopes`,
default S), the host-required scopes H (`requiredScopes`), the explicit scopes E
(`prepare(..., { requiredScopes })`), the stored grant, the generation whose
token the challenged request sent, and the challenge. Only R = H ∪ E ∪ Ch (the
scopes of a Bearer 403 `insufficient_scope`) is mandatory: H is mandatory for
every operation; S, a preset's `scopes` and a 401's `scope` are never part of R.
The first matching step wins:

0. A 401 retires the rejected token first, whatever the outcome.
1. S ⊄ C, a preset `scopes` that differs from S (an omitted one is no
   constraint), or an invalid scope token: `invalid_configuration`.
2. An unparseable or ambiguous challenge (a bad auth-param, two Bearer
   challenges, a duplicated parameter, a malformed `scope`), a 403 that is not
   `insufficient_scope`, or a 403 `insufficient_scope` without `scope` when H ∪ E
   is empty: `access_denied`, no scopes.
3. A 401's `scope` within C is requested only by a client-credentials
   acquisition in that same operation; it is never stored or required.
4. R ⊄ C: `access_denied` carrying R, decided locally with no network I/O when
   the binding or preset is known (an unbound target first fetches only its
   protected-resource metadata, which client selection needs).
5. A 403 `insufficient_scope` whose R the grant behind the rejected token (or
   any grant, when no token was sent) records as granted: `access_denied`
   carrying R, no replay and no login. A newer stored generation covering R is
   used instead.
6. A valid token covering R is used; 7. a refresh token whose grant covers R
   refreshes; 8. client credentials acquire previous ∪ ((S ∪ R ∪ hint) ∩ C);
   9. PKCE: `prepare` creates a login requesting previous ∪ ((S ∪ R) ∩ C) and
   storing R; any other entry point fails `interaction_required` carrying R
   (pass it back with `oauth.prepare(context, budget, { requiredScopes })`).

A refreshed, acquired or completed grant that does not cover R fails
`access_denied` carrying R, with the grant (and any rotated refresh token)
persisted. Scope sets on errors are deduplicated and sorted in ascending byte
order. Scopes are attached only by `decide` and by `complete`'s coverage check:
errors from host callbacks, stores, the host network and the token endpoint never
carry them. Hooks replays a challenged request with the challenge, its status
(`challengeStatus`) and the rejected credential (`rejectedCredential`) on the
context, so the replay is decided as the same operation.

Every error thrown by `complete()` carries `loginEnded`, and only those errors do:
`true` once the login named by the callback's `state` no longer exists (it was
consumed, had expired, had ended or was unknown), `false` while it is still
pending (an invalid callback, a host policy failure before the claim, an invalid
budget). When the claim's outcome is uncertain (a store error or the deadline),
the store is re-read on a fresh short budget: `true` if the login is gone, `false`
if it is pending or cannot be determined. Native cancellation and deadline errors
keep their identity; a reason that cannot carry the flag (a primitive or frozen
object) is wrapped in an `AbortError` DOMException whose `cause` is that reason.
A pending login written by an older release has no stored R: its prepare-time H
applies when the record holds it, else the current H.

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
grant`. Extra scopes are ignored. At use, effective scopes are the grant ∩ the
current ceiling, and only R (host-required, explicit and 403 challenge scopes) is
mandatory; 401 `scope` hints are not. The ceiling governs what the SDK requests
and records; it does not constrain what an issued token can do.

## Client registration

Each grant's `client_id` comes from one source, chosen per issuer and flow:

1. **Pre-registered**: `ClientConfig.clientId` (or the preset's). It always wins.
2. **Client ID Metadata Document**: PKCE only, when `clientMetadataDocument`
   (`{ url, redirectUris }`) is set and the issuer advertises
   `client_id_metadata_document_supported: true`. The URL is the `client_id`; the
   SDK never fetches it. The redirect must equal one of `redirectUris`; a loopback
   redirect is compared without its port (RFC 8252 §7.3).
3. **Dynamic registration (RFC 7591)**: when `registration` (`{ clientName,
   softwareId?, softwareVersion?, scopes?, initialAccessTokenRef? }`) is set on the
   config for that exact issuer and it advertises `registration_endpoint`.
   Client credentials also need `secrets`, a host `SecretStore`
   (`put`/`get`/`delete` by opaque reference); secrets never enter `store`. An
   initial access token reference is resolved with `secrets.get` and sent only to
   that issuer's endpoint (`checkDestination` purpose `"registration"`).

Otherwise the operation fails `credential_unavailable`. The selection is recorded
on the binding and survives metadata changes until host policy changes it.

PKCE registration works as in MCP clients: only host `prepare` registers, inside
the login it creates, with that login's redirect (and `application_type:
"native"` for a loopback redirect). There is no registration record: completion
stores the issued `client_id` in the grant with its tokens, and refresh uses it.
A re-registered client never moves the grant. `invalid_client` at completion ends
only that login (`interaction_required`; the stored grant is kept); at refresh it
deletes the grant if it still holds the presented client and refresh token, and
returns `interaction_required`. Any secret issued to a PKCE client is ignored.

Client credentials keep one `registration` record per namespace and issuer,
created once under `coordinate` and reused by every client-credentials grant
there. It stores the registered token-endpoint auth method and a secret reference.
It is replaced when the secret expires or cannot be resolved, or when the token
endpoint answers `invalid_client` (at most once per operation; a repeated one is
`credential_unavailable`). After a failed registration a `registration_failure`
record, shared through the store, holds off further requests (`registrationBackoff`,
default 1 minute doubling to 1 hour, honouring `Retry-After`); meanwhile
operations fail with the last failure's code, so a retryable failure stays
`provider_failed` (`retry`). A repeated `invalid_client` for a replacement client
also counts as a failed registration. Host `prepare` bypasses the backoff. Host
`prepare` does not replace a usable client-credentials registration, so a changed
registration policy takes effect only when the secret expires, the token endpoint
answers `invalid_client`, or the host calls
`prepare(context, budget, { forceRegistration: true })`, which registers anew,
replaces the record (deleting its old secret) and acquires a token with the new client.

The built-in `auth()` provider uses pre-registered clients only: it has no
coordinated store, secret hook or `prepare`, so a missing `clientId` fails
`credential_unavailable`. It calls the same `decide` (H is
`OAuthClient.requiredScopes`): with a known client, steps 1-4 run before any
network I/O, only a 401 rediscovers, a challenge's requirement applies to that
operation only (the discovery cache keeps host policy), and its `challenge`
decides the challenge too, so an unreplayed request still fails. With an
`authorize` hook, PKCE signs in inline (decide's `prepare`); without one it fails
`interaction_required`. Host errors it surfaces carry no scopes.

## Rotation, rejection and failure

A delivery that fails on authentication reports it in its `DeliveryDiagnostic`
as `auth: { code, recovery, requiredScopes? }`, the redacted `AuthError` fields.
`recovery: "login"` (for example `interaction_required`) tells the host to run
its login (`prepare`) for that diagnostic's `backendId`, passing `requiredScopes`.

Refresh runs inside host coordination, reloads the latest generation, and uses
CAS for replacement; concurrent callers reuse the refreshed grant. Refresh uses
the persisted authorization-server metadata; `prepare` and challenge handling
rediscover outside store locks before a renewal or login, falling back to it during
an outage. If the token
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
locally allowed ceiling (beyond it, `access_denied` carries R), and only for the
challenged operation: requirements are never persisted. Without a challenge
scope, supply explicit host-required scopes or the challenge is denied. Hooks
alone decides replay (see the README).
