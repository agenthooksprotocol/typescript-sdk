import { AuthError, classifyAuthError, type DeliveryAuthContext } from "../client/auth.js";
import { bearerParameters, challengeScopes } from "../client/challenge.js";
export { challengeScopes } from "../client/challenge.js";
import { processDiscoveryResponse, type AuthorizationServer } from "oauth4webapi";
import type { ClientConfig, ManagedOAuthOptions, NetworkPurpose, Operation, ResolvedTarget, StoredBinding } from "./types.js";

export type CachedBinding = Pick<StoredBinding, "issuer" | "resource" | "metadata">;

/** Cancellation and deadlines keep native identity: AbortError reason or TimeoutError. */
export function active(operation: Operation): void {
  operation.signal.throwIfAborted();
  if (Date.now() >= operation.deadline) throw new DOMException("OAuth operation deadline exceeded", "TimeoutError");
}

export function https(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new AuthError("untrusted_destination"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || value.includes("#")) {
    throw new AuthError("untrusted_destination");
  }
  return url;
}

const transport = new WeakSet<AuthError>(), refusals = new WeakSet<AuthError>(), own = new WeakSet<AuthError>();
/**
 * An `access_denied` or `interaction_required` from the SDK's own scope checks,
 * carrying the operation's full required set. Only these keep scopes at the API boundary.
 */
export function scoped(code: "access_denied" | "interaction_required", required: readonly string[] | undefined): AuthError {
  const error = new AuthError(code, required);
  own.add(error);
  return error;
}
/**
 * A decision from local scope policy alone (a ceiling refusal, or requested scopes
 * outside the ceiling): rediscovery cannot repair it, so it never triggers network I/O.
 */
export function isLocalScopePolicy(error: unknown): boolean {
  return error instanceof AuthError && (own.has(error) || localPolicies.has(error));
}
const localPolicies = new WeakSet<AuthError>();
function localScopePolicy(error: AuthError): AuthError { localPolicies.add(error); return error; }
/** Contexts of a 401 challenge: their `scope` is never a requirement, whatever `error` says. */
const unauthorizedContexts = new WeakSet<object>();
export function markUnauthorized<T extends object>(context: T): T { unauthorizedContexts.add(context); return context; }
/** Host-policy errors (client selection, destination checks, stores, budgets) never carry scopes. */
export function withoutHostScopes(error: AuthError): AuthError {
  return error.requiredScopes === undefined || own.has(error) ? error : new AuthError(error.code);
}
/** True when the host's selectClient rejected the binding: the only lookup policy refusal. */
export function isPolicyRefusal(error: unknown): boolean {
  return error instanceof AuthError && refusals.has(error);
}
/** Failures before the request reached the server: DNS, TCP connect, TLS handshake. */
const PRE_SEND = /^(?:ENOTFOUND|EAI_AGAIN|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|EADDRNOTAVAIL|UND_ERR_CONNECT_TIMEOUT|EPROTO|CERT_.*|.*_CERT_.*|UNABLE_TO_.*|ERR_TLS_.*|ERR_SSL_.*)$/;
function preSend(error: unknown): boolean {
  // Node's fetch wraps the socket error in a TypeError; inspect the cause chain.
  for (let current = error, depth = 0; current && depth < 4; depth++) {
    let code: unknown, cause: unknown;
    try { ({ code, cause } = current as { code?: unknown; cause?: unknown }); } catch { return false; }
    if (typeof code === "string" && PRE_SEND.test(code)) return true;
    current = cause;
  }
  return false;
}
/** Tag a renewal failure where the token endpoint provably did not process the request. */
export function markTransport(error: AuthError): AuthError { transport.add(error); return error; }
export function isTransportFailure(error: unknown): boolean {
  return error instanceof AuthError && transport.has(error);
}

/** The host must enforce DNS/connect policy, not merely inspect this URL. */
export async function checkedFetch(
  url: string,
  init: RequestInit,
  purpose: NetworkPurpose,
  options: ManagedOAuthOptions,
  operation: Operation,
): Promise<Response> {
  const destination = https(url);
  const original = destination.href;
  active(operation);
  try {
    await options.checkDestination(destination, purpose, operation);
  } catch (error) {
    active(operation);
    throw classifyAuthError(error, "untrusted_destination");
  }
  active(operation);
  if (destination.href !== original) throw new AuthError("untrusted_destination");
  // Caller cancellation is honoured only before a token request is sent. Receiving its
  // headers and body is bounded by the commit timeout instead, so an abort mid-flight
  // never cuts off a response that may carry a rotated refresh token. fetch cannot report
  // when bytes were written, so "sent" is approximated as "policyFetch was called":
  // checkDestination and earlier steps stay abortable, and the caller always gets its
  // abort promptly, but a stalled connect keeps the grant lock until the commit timeout.
  const transfer: Operation = purpose === "token"
    ? Object.freeze({ signal: AbortSignal.timeout(options.commitTimeoutMs ?? 30_000), deadline: Date.now() + (options.commitTimeoutMs ?? 30_000) })
    : operation;
  let response: Response;
  try {
    response = await options.policyFetch(url, { ...init, redirect: "error", signal: transfer.signal }, { purpose, operation: transfer });
  } catch (error) {
    if (purpose !== "token") active(operation);
    const classified = classifyAuthError(error);
    throw classified.code === "provider_failed" && preSend(error) ? markTransport(classified) : classified;
  }
  // A token response is never dropped for a late caller abort: its rotated refresh
  // token must still be committed.
  if (purpose !== "token") active(operation);
  if (response.redirected || (response.url !== "" && response.url !== url)) {
    throw new AuthError("untrusted_destination");
  }
  return response;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new AuthError("discovery_failed");
  return value as Record<string, unknown>;
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value) || value.some(item => typeof item !== "string" || item.length === 0)) {
    throw new AuthError("discovery_failed");
  }
  return value as string[];
}

async function metadataAt(urls: readonly string[], options: ManagedOAuthOptions, operation: Operation, expectedResources?: ReadonlyMap<string, string>, expectedIssuer?: string): Promise<Record<string, unknown>> {
  for (const url of new Set(urls)) {
    const response = await checkedFetch(url, { headers: { Accept: "application/json" } }, "metadata", options, operation);
    // A malformed or rejected document must never cause a downgrade to another location.
    if (response.status === 404) continue;
    if (!response.ok) throw new AuthError("discovery_failed");
    try {
      const body: unknown = expectedIssuer === undefined
        ? await response.json()
        : await processDiscoveryResponse(new URL(expectedIssuer), response);
      active(operation);
      const metadata = record(body);
      // Signed metadata needs a host verifier; never use unverified JWT claims.
      if (metadata.signed_metadata !== undefined) throw new AuthError("unsupported_binding");
      if (expectedResources && metadata.resource !== expectedResources.get(url)) throw new AuthError("discovery_failed");
      return metadata;
    } catch (error) {
      active(operation);
      throw classifyAuthError(error, "discovery_failed");
    }
  }
  throw new AuthError("discovery_failed");
}

function resourceCovers(resource: string, endpoint: string): void {
  const base = https(resource), target = https(endpoint);
  if ((resource.includes("?") && resource !== endpoint) || base.origin !== target.origin ||
      !(target.pathname === base.pathname || target.pathname.startsWith(base.pathname.replace(/\/$/, "") + "/"))) {
    throw new AuthError("discovery_failed");
  }
}

function validateClient(client: ClientConfig): void {
  if (!client || typeof client.issuer !== "string" || typeof client.resource !== "string" ||
      (client.clientId !== undefined && (typeof client.clientId !== "string" || !client.clientId.trim())) ||
      !["authorization_code_pkce", "client_credentials"].includes(client.flow)) throw new AuthError("invalid_configuration");
  const issuer = https(client.issuer);
  https(client.resource);
  if (issuer.search || client.issuer.includes("?")) throw new AuthError("invalid_configuration");
  if (!Array.isArray(client.scopes) || client.scopes.some(scope => typeof scope !== "string" || !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) {
    throw new AuthError("invalid_configuration");
  }
  const document = client.clientMetadataDocument, policy = client.registration;
  const text = (value: unknown) => typeof value === "string" && value.length > 0;
  if ((document !== undefined && (!document || typeof document.url !== "string" || !Array.isArray(document.redirectUris) ||
        !document.redirectUris.every(text))) ||
      (policy !== undefined && (!policy || !text(policy.clientName) ||
        [policy.softwareId, policy.softwareVersion, policy.initialAccessTokenRef].some(value => value !== undefined && !text(value)) ||
        (policy.scopes !== undefined && (!Array.isArray(policy.scopes) ||
          policy.scopes.some(scope => typeof scope !== "string" || !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))))))) {
    throw new AuthError("invalid_configuration");
  }
}

/**
 * With `cached`, performs no network I/O: only local client policy runs.
 * `explicit` (validated host `prepare` requirements) only joins the ceiling check.
 * Completion passes `enforceRequired = false`: it enforces the login's stored R
 * against the grant instead, after the login is claimed.
 */
export async function resolveTarget(context: DeliveryAuthContext, options: ManagedOAuthOptions, operation: Operation, cached?: CachedBinding,
  explicit: readonly string[] = [], enforceRequired = true): Promise<ResolvedTarget> {
  try {
    return await discover(context, options, operation, cached, explicit, enforceRequired);
  } catch (error) {
    active(operation);
    throw classifyAuthError(error, "discovery_failed");
  }
}

async function discover(context: DeliveryAuthContext, options: ManagedOAuthOptions, operation: Operation, cached: CachedBinding | undefined,
  explicit: readonly string[], enforceRequired: boolean): Promise<ResolvedTarget> {
  active(operation);
  const binding = context.authentication;
  if (binding !== undefined && binding.type !== "oauth") throw new AuthError("unsupported_binding");
  const endpoint = https(context.url);
  let challenge: Map<string, string>;
  try {
    challenge = bearerParameters(context.challenge);
  } catch {
    // An unparseable challenge (for example a duplicated parameter) fails closed, with no scopes.
    throw localScopePolicy(new AuthError("access_denied"));
  }
  const advertised = challenge.get("resource_metadata");
  if (advertised !== undefined && advertised === "") throw new AuthError("discovery_failed");
  const path = endpoint.pathname === "/" ? "" : endpoint.pathname;
  const query = endpoint.href.includes("?") ? endpoint.href.slice(endpoint.href.indexOf("?")) : "";
  const specific = `${endpoint.origin}/.well-known/oauth-protected-resource${path}${query}`;
  const root = `${endpoint.origin}/.well-known/oauth-protected-resource`;
  // RFC 9728 section 3.3 binds the returned identifier to the discovery source.
  const expected = advertised !== undefined
    ? new Map([[advertised, context.url]])
    : new Map([[specific, context.url], [root, endpoint.origin]]);
  // A preset already fixes the principal; PRM must not override or gate it.
  const protectedResource: Record<string, unknown> = binding
    ? { resource: binding.resource, authorization_servers: [binding.issuer] }
    : cached ? { resource: cached.resource, authorization_servers: [cached.issuer] }
    : await metadataAt(advertised !== undefined ? [advertised] : [specific, root], options, operation, expected);
  if (typeof protectedResource.resource !== "string") throw new AuthError("discovery_failed");
  const resource = protectedResource.resource;
  resourceCovers(resource, context.url);
  const issuers = strings(protectedResource.authorization_servers);
  if (issuers.length === 0) throw new AuthError("discovery_failed");
  for (const value of issuers) {
    const issuer = https(value);
    if (issuer.search || value.includes("?")) throw new AuthError("discovery_failed");
  }
  if (protectedResource.bearer_methods_supported !== undefined &&
      !strings(protectedResource.bearer_methods_supported).includes("header")) throw new AuthError("discovery_failed");
  if (binding && (binding.resource !== resource || !issuers.includes(binding.issuer))) throw new AuthError("invalid_configuration");
  let selected: ClientConfig;
  try {
    selected = await options.selectClient(Object.freeze(binding ? [binding.issuer] : [...issuers]), resource, context, operation);
  } catch (error) {
    active(operation);
    const refusal = withoutHostScopes(classifyAuthError(error, "credential_unavailable"));
    refusals.add(refusal);
    throw refusal;
  }
  active(operation);
  validateClient(selected);
  // A pre-registered confidential client needs its secret; a registered one gets it from `secrets`.
  if (selected.clientId !== undefined && (selected.flow === "client_credentials" || binding?.clientSecretRef !== undefined) &&
      (typeof selected.clientSecret !== "string" || !selected.clientSecret)) throw new AuthError("credential_unavailable");
  if (!issuers.includes(selected.issuer) || selected.resource !== resource) throw new AuthError("invalid_configuration");
  if (binding && (selected.issuer !== binding.issuer || selected.resource !== binding.resource ||
      selected.clientId !== binding.clientId || selected.flow !== binding.flow ||
      JSON.stringify([...new Set(selected.scopes)].sort()) !== JSON.stringify([...new Set(binding.scopes ?? [])].sort()))) throw new AuthError("invalid_configuration");
  // Snapshot host-owned configuration before subsequent asynchronous policy calls.
  const scopePolicy = selected;
  const allowedScopes = scopePolicy.allowedScopes ?? selected.scopes;
  const requiredScopes = [...(scopePolicy.requiredScopes ?? [])];
  const validScope = (scope: unknown): scope is string => typeof scope === "string" && /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope);
  if (!Array.isArray(allowedScopes) || !allowedScopes.every(validScope) ||
      !Array.isArray(scopePolicy.requiredScopes ?? []) || !requiredScopes.every(validScope) ||
      selected.scopes.some(scope => !allowedScopes.includes(scope))) throw localScopePolicy(new AuthError("invalid_configuration"));
  const hostRequiredScopes = Object.freeze([...new Set(requiredScopes)]);
  // A 401 `scope` (as in MCP clients) only widens what the next acquisition requests,
  // within the ceiling; only a 403 insufficient_scope adds a requirement.
  let scopes: ReturnType<typeof challengeScopes>;
  try { scopes = challengeScopes(challenge, unauthorizedContexts.has(context)); }
  catch (error) { throw localScopePolicy(error as AuthError); }
  const { required, hinted } = scopes;
  requiredScopes.push(...required);
  // A requirement (host, explicit or challenged) outside the ceiling is refused, naming the full required set.
  const operationScopes = [...requiredScopes, ...explicit];
  if (enforceRequired && operationScopes.some(scope => !allowedScopes.includes(scope))) throw scoped("access_denied", operationScopes);
  const client: ClientConfig = Object.freeze({ ...selected,
    scopes: Object.freeze([...new Set([...selected.scopes, ...hinted.filter(scope => allowedScopes.includes(scope))])]),
    allowedScopes: Object.freeze([...new Set(allowedScopes)]),
    requiredScopes: Object.freeze([...new Set(requiredScopes)]),
  });
  const issuer = https(client.issuer);
  // RFC 8414 section 3.1 removes a terminating slash for metadata lookup only.
  const issuerPath = issuer.pathname.replace(/\/$/, "");
  const metadata = cached?.metadata && cached.issuer === client.issuer ? cached.metadata as unknown as Record<string, unknown> : await metadataAt([
    `${issuer.origin}/.well-known/oauth-authorization-server${issuerPath}`,
    `${issuer.origin}/.well-known/openid-configuration${issuerPath}`,
    `${issuer.origin}${issuerPath.replace(/\/$/, "")}/.well-known/openid-configuration`,
  ], options, operation, undefined, client.issuer);
  if (metadata.issuer !== client.issuer || typeof metadata.token_endpoint !== "string") throw new AuthError("discovery_failed");
  if (metadata.protected_resources !== undefined &&
      !strings(metadata.protected_resources).includes(client.resource)) throw new AuthError("discovery_failed");
  https(metadata.token_endpoint);
  if (metadata.authorization_endpoint !== undefined) {
    if (typeof metadata.authorization_endpoint !== "string") throw new AuthError("discovery_failed");
    https(metadata.authorization_endpoint);
  }
  if (client.flow === "client_credentials" &&
      (metadata.grant_types_supported === undefined || !strings(metadata.grant_types_supported).includes("client_credentials"))) {
    throw new AuthError("unsupported_binding");
  }
  if (client.flow === "authorization_code_pkce") {
    if (typeof metadata.authorization_endpoint !== "string" ||
        metadata.code_challenge_methods_supported === undefined ||
        !strings(metadata.code_challenge_methods_supported).includes("S256") ||
        (metadata.grant_types_supported !== undefined && !strings(metadata.grant_types_supported).includes("authorization_code"))) {
      throw new AuthError("unsupported_binding");
    }
  }
  return { client, metadata: metadata as unknown as AuthorizationServer, hostRequiredScopes };
}
