import { AuthError, normalizeAuthTarget, classifyAuthError } from "../client/auth.js";
import type { AuthChallengeContext, AuthErrorCode, DeliveryAuthContext, DeliveryAuthProvider, DeliveryCredential, PreparedEndpoint } from "../client/auth.js";
import { active, https, isPolicyRefusal, resolveTarget, type ScopeGate } from "./discovery.js";
import { classify, coverage, decide, parseChallenge, type Challenge, type DecisionConfig, type DecisionGrant, type DecisionOperation } from "../client/decision.js";
import {
  acquireClientCredentials, exchangeCode, isInvalidClient, isTransportFailure, pkce, refreshCredential, startLogin, validateCallback,
} from "./protocol.js";
import type { TokenResult } from "./protocol.js";
import { chooseSource, cimdRedirect, clientIdentity, dcr, failureKey, frame, register, registrationKey, registrationRequest } from "./registration.js";
import type { AcceptedRegistration, AuthMethod } from "./registration.js";
import type {
  ClientConfig, ClientSelection, ManagedOAuthOptions, Operation, ResolvedTarget, StoredBinding, StoredGrant, StoredPendingIndex, StoredPendingLogin,
  StoredRecord, StoredRegistration, StoredRegistrationFailure, TokenValue,
} from "./types.js";
export type {
  ClientConfig, ClientMetadataDocument, ClientSelection, ClientSource, ManagedOAuthOptions, NetworkPurpose, Operation, PolicyFetch,
  RegistrationPolicy, SecretStore, StoredBinding, StoredGrant, StoredPendingIndex, StoredPendingLogin, StoredRecord, StoredRegistration,
  StoredRegistrationFailure, TokenStore, TokenValue,
} from "./types.js";
export { clientIdentity, frame, registrationKey } from "./registration.js";

/**
 * Plain-data handle for a pending login, which `complete` finds by the callback's
 * `state`. Keep it private: the authorization URL carries OAuth state.
 */
export type PendingLogin = Readonly<{ type: "pending_login"; authorizationUrl: string; expiresAt: number; state: string }>;
/** `credential.token` is non-enumerable, so it is absent from JSON and inspection output. */
export type Ready = Readonly<{ type: "ready"; credential: DeliveryCredential }>;
export type PrepareResult = Ready | PendingLogin;
export interface PrepareOptions {
  /** Explicit operation requirements, such as `AuthError.requiredScopes` from a step-up challenge. */
  readonly requiredScopes?: readonly string[];
  /**
   * This login's exact redirect, instead of `ClientConfig.redirectUri`: for example
   * a loopback listener on a fresh ephemeral port, as MCP clients bind per login.
   */
  readonly redirectUri?: string;
  /**
   * Client credentials with DCR: register anew and replace the stored registration
   * even when it is usable, for example after changing the registration policy.
   */
  readonly forceRegistration?: boolean;
}

const MAX_LOGIN_LIFETIME = 600_000;
const EXPIRY_SKEW = 30_000;
type Mode = "host" | "delivery" | "lookup";
interface Attempt { readonly key: string; readonly generation: string; readonly identity: string }
/** A target whose client source is resolved, with its grant-key client identity. */
interface Selected extends ResolvedTarget {
  readonly selection: ClientSelection;
  readonly identity: string;
  /** Client credentials with DCR only. */
  readonly registration?: Registered;
}
interface Registered { readonly key: string; readonly record?: StoredRegistration; readonly secret?: string; readonly usable: boolean }
/** Up-front lookup outcome for a store miss or host policy refusal: send anonymously. */
const LOOKUP_MISS = Object.freeze({ type: "lookup_miss" as const });

export function bindingKey(namespace: string, context: DeliveryAuthContext): string {
  normalizeAuthTarget(context);
  return frame("ahp.oauth.binding:", [namespace, context.backendId, context.purpose, context.url]);
}
/**
 * Grant identity: the configured client identity (`preregistered:<id>`, `cimd:<url>` or
 * `dcr`), never an issued client_id, ceiling, secret, auth method or scope set.
 */
export function grantKey(namespace: string, context: DeliveryAuthContext,
  client: Pick<ClientConfig, "issuer" | "resource" | "flow" | "grantPartition">, identity: string): string {
  if (client.grantPartition !== undefined && (typeof client.grantPartition !== "string" || !client.grantPartition)) {
    throw new AuthError("invalid_configuration");
  }
  if (typeof identity !== "string" || !identity) throw new AuthError("credential_unavailable");
  return frame("ahp.oauth.grant:", [namespace, client.issuer, client.resource, identity, client.flow,
    client.grantPartition === undefined ? `binding:${bindingKey(namespace, context)}` : `shared:${client.grantPartition}`]);
}
function pendingKey(namespace: string, state: string): string {
  return frame("ahp.oauth.pending:", [namespace, state]);
}
function pendingIndexKey(grant: string): string {
  return frame("ahp.oauth.pending-index:", [grant]);
}
const ceilingOf = (client: ClientConfig) => client.allowedScopes ?? client.scopes;
function snapshotContext(context: DeliveryAuthContext): DeliveryAuthContext {
  normalizeAuthTarget(context);
  const { authentication, ...rest } = context;
  if (!authentication) return Object.freeze(rest);
  const binding = Object.freeze({ ...authentication,
    ...(authentication.type === "oauth" && authentication.scopes !== undefined
      ? { scopes: Object.freeze([...authentication.scopes]) as unknown as string[] } : {}),
  });
  return Object.freeze({ ...rest, authentication: binding });
}
/** The durable part of a delivery context: no signal, challenge or caches. */
function durableContext(context: DeliveryAuthContext): StoredPendingLogin["context"] {
  return { backendId: context.backendId, purpose: context.purpose, url: context.url,
    ...(context.authentication ? { authentication: structuredClone(context.authentication) } : {}) };
}

/** Settle on work or abort, whichever comes first; host callbacks may ignore signals. */
function race<T>(signal: AbortSignal, work: Promise<T>): Promise<T> {
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
/** One cancellation boundary: caller budget, optional context signal and absolute deadline. */
async function run<T>(budget: Operation, extra: AbortSignal | undefined, work: (operation: Operation) => Promise<T>): Promise<T> {
  const { signal: input, deadline } = budget ?? {};
  if (!input || typeof input.throwIfAborted !== "function" || !Number.isFinite(deadline)) throw new AuthError("invalid_configuration");
  input.throwIfAborted();
  extra?.throwIfAborted();
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new DOMException("Operation deadline exceeded", "TimeoutError");
  const signal = AbortSignal.any([input, ...(extra ? [extra] : []), AbortSignal.timeout(Math.min(remaining, 2_147_483_647))]);
  try {
    return await race(signal, Promise.resolve().then(() => work(Object.freeze({ signal, deadline }))));
  } catch (error) {
    // Section 4: only decide's and complete's own outcomes keep scopes.
    throw classify(classifyAuthError(error, "provider_failed", signal));
  }
}

/**
 * A `complete()` failure carrying `loginEnded`. An AuthError is copied (code, recovery
 * and scopes unchanged). A native cancellation or deadline error keeps its identity;
 * a reason that cannot carry the flag (a primitive or a frozen object) is wrapped in an
 * `AbortError` DOMException whose `cause` is the original reason.
 */
function loginEndedError(error: unknown, ended: boolean): unknown {
  let target = error instanceof AuthError ? new AuthError(error.code, error.requiredScopes) : error;
  if (typeof target !== "object" || target === null || !Object.isExtensible(target)) {
    const wrapped = new DOMException("OAuth operation cancelled", "AbortError");
    Object.defineProperty(wrapped, "cause", { value: error, enumerable: false });
    target = wrapped;
  }
  // Configurable and writable: the caller's own reason may be annotated again later.
  Object.defineProperty(target, "loginEnded", { value: ended, enumerable: true, configurable: true, writable: true });
  return target;
}

/** No browser, listener, global fetch, background refresh or default storage. */
export function managedOAuth(configuration: ManagedOAuthOptions) {
  if (!configuration || typeof configuration.namespace !== "string" || !configuration.namespace.trim() ||
      !configuration.store || typeof configuration.store.load !== "function" ||
      typeof configuration.store.compareAndSet !== "function" ||
      typeof configuration.store.coordinate !== "function" ||
      typeof configuration.policyFetch !== "function" ||
      typeof configuration.checkDestination !== "function" ||
      typeof configuration.selectClient !== "function" ||
      (configuration.persistPendingLogins !== undefined && typeof configuration.persistPendingLogins !== "boolean") ||
      (configuration.secrets !== undefined && (!configuration.secrets || ["put", "get", "delete"].some(name =>
        typeof (configuration.secrets as unknown as Record<string, unknown>)[name] !== "function")))) {
    throw new AuthError("invalid_configuration");
  }
  const options = { ...configuration };
  const { store, namespace, secrets } = options;
  const backoffInitial = options.registrationBackoff?.initialMs ?? 60_000;
  const backoffMax = options.registrationBackoff?.maxMs ?? 3_600_000;
  if (![backoffInitial, backoffMax].every(value => Number.isFinite(value) && value >= 0) ||
      backoffInitial > backoffMax) throw new AuthError("invalid_configuration");
  const loginLifetime = options.loginLifetimeMs ?? MAX_LOGIN_LIFETIME;
  const commitTimeout = options.commitTimeoutMs ?? 30_000;
  const maxPending = options.maxPendingLogins ?? 5;
  const persist = options.persistPendingLogins === true;
  if (!Number.isFinite(loginLifetime) || loginLifetime <= 0 || loginLifetime > MAX_LOGIN_LIFETIME ||
      !Number.isFinite(commitTimeout) || commitTimeout <= 0 ||
      !Number.isSafeInteger(maxPending) || maxPending < 1) throw new AuthError("invalid_configuration");
  /**
   * Persisting a token response is not tied to the caller's budget: the server has
   * already spent the old refresh token, so losing the rotated one would replay it.
   */
  const commit = (): Operation => Object.freeze({ signal: AbortSignal.timeout(Math.min(commitTimeout, 2_147_483_647)), deadline: Date.now() + commitTimeout });
  const attempts = new WeakMap<object, Attempt>();
  /** `decide` failures from the local gate (steps 1-4): never repaired by rediscovery. */
  const gated = new WeakSet<AuthError>();
  /** Process-owned pending logins by state, oldest first. */
  const local = new Map<string, StoredPendingLogin>();

  async function read<K extends StoredRecord["kind"]>(key: string, kind: K, operation: Operation): Promise<Extract<StoredRecord, { kind: K }> | undefined> {
    const value = await race(operation.signal, store.load(key, operation.signal));
    if (value === undefined) return undefined;
    const record = value as unknown as Record<string, unknown>;
    if (typeof value !== "object" || value === null || value.kind !== kind || typeof value.generation !== "string" || !value.generation ||
        (kind === "grant" && (!Array.isArray(record.scopes) ||
          (record.token !== undefined && typeof record.token !== "string") ||
          (record.clientId !== undefined && typeof record.clientId !== "string") ||
          (record.expiresAt !== undefined && !Number.isFinite(record.expiresAt)))) ||
        (kind === "registration" && (typeof record.clientId !== "string" || typeof record.secretRef !== "string" ||
          !["client_secret_basic", "client_secret_post"].includes(record.tokenEndpointAuthMethod as string))) ||
        (kind === "registration_failure" && (!Number.isSafeInteger(record.attempts) ||
          !Number.isFinite(record.nextAttemptAt) || typeof record.code !== "string")) ||
        (kind === "pending_login" && (typeof record.state !== "string" || typeof record.verifier !== "string" ||
          typeof record.grantKey !== "string" || !Number.isFinite(record.expiresAt))) ||
        (kind === "pending_index" && (!Array.isArray(record.states) || !record.states.every(state => typeof state === "string")))) {
      throw new AuthError("credential_unavailable");
    }
    // Snapshot: a live host object must not change what we compare-and-set against.
    return structuredClone(value) as Extract<StoredRecord, { kind: K }>;
  }
  async function write(key: string, expected: string | undefined, value: StoredRecord | undefined, operation: Operation): Promise<boolean> {
    operation.signal.throwIfAborted();
    return race(operation.signal, store.compareAndSet(key, expected, value, operation.signal));
  }
  async function saveGrant(key: string, expected: string | undefined, token: Omit<StoredGrant, "kind" | "generation">, operation: Operation): Promise<StoredGrant> {
    const value: StoredGrant = { ...token, kind: "grant", scopes: [...token.scopes], generation: crypto.randomUUID() };
    if (!await write(key, expected, value, operation)) throw new AuthError("provider_failed");
    return value;
  }
  function identity(context: DeliveryAuthContext): string {
    return bindingKey("", context);
  }
  function ready(grant: StoredGrant, key: string, binding: string): Ready {
    if (!grant.token || !/^[A-Za-z0-9\-._~+/]+=*$/.test(grant.token)) throw new AuthError("credential_unavailable");
    const attempt = Object.freeze({});
    attempts.set(attempt, { key, generation: grant.generation, identity: binding });
    const credential = { type: "bearer" as const, attempt };
    Object.defineProperty(credential, "token", { value: grant.token, enumerable: false });
    return Object.freeze({ type: "ready", credential: Object.freeze(credential as DeliveryCredential) });
  }
  /** S, C, H, E and the preset's scopes, as `decide` reads them. */
  function configOf(client: ClientConfig, explicit: readonly string[], preset: readonly string[] | undefined): DecisionConfig {
    return { flow: client.flow, requested: client.scopes, ceiling: ceilingOf(client), hostRequired: client.requiredScopes ?? [], explicit,
      ...(preset === undefined ? {} : { presetScopes: preset }) };
  }
  function presetOf(context: DeliveryAuthContext): readonly string[] | undefined {
    const binding = context.authentication;
    return binding?.type === "oauth" && binding.scopes !== undefined ? binding.scopes : undefined;
  }
  /** The stored grant as `decide` sees it; `forced` (a forced re-registration) is never used or refreshed. */
  function grantOf(grant: StoredGrant | undefined, target: Selected, forced = false): DecisionGrant | undefined {
    if (!grant) return undefined;
    const tokenValid = !forced && grant.token !== undefined && (grant.expiresAt === undefined || grant.expiresAt > Date.now() + EXPIRY_SKEW);
    // A DCR grant refreshes only with the client issued to the login that produced it.
    const refresh = !forced && grant.refreshToken !== undefined && (target.selection.source !== "dcr" || grant.clientId !== undefined);
    return { generation: grant.generation, granted: grant.scopes, tokenValid, refresh };
  }
  /** The challenged status a context carries (401 for `challenged` without a header). */
  function statusOf(context: DeliveryAuthContext | undefined): number | undefined {
    if (!context) return undefined;
    try { return parseChallenge(context.challengeStatus, context.challenge, context.challenged === true).status; } catch { return undefined; }
  }
  function challengeOf(context: DeliveryAuthContext): Challenge {
    return parseChallenge(context.challengeStatus, context.challenge, context.challenged === true);
  }
  /** The attempt behind a credential this provider issued for this binding. */
  function attemptOf(credential: DeliveryCredential | undefined, context: DeliveryAuthContext): Attempt | undefined {
    const owner = credential ? attempts.get(credential.attempt as object) : undefined;
    if (credential && (!owner || owner.identity !== identity(context))) throw new AuthError("invalid_configuration");
    return owner;
  }
  /**
   * Step 0 before any target or configuration check: a 401 retires the token of the
   * attempt `credential` names, whenever its grant can be identified (an attempt this
   * provider issued for the same binding, or one whose target no longer normalizes).
   */
  async function retireFirst(status: number | undefined, credential: DeliveryCredential | undefined, context: unknown): Promise<void> {
    if (status !== 401 || !credential || typeof credential !== "object") return;
    let owner: Attempt | undefined;
    try { owner = attempts.get(credential.attempt as object); } catch { return; }
    if (!owner) return;
    let same = true;
    try { same = owner.identity === identity(context as DeliveryAuthContext); } catch { /* An invalid target: the attempt still names its grant. */ }
    if (same) await retire(owner, commit());
  }
  /** True when the caller's budget is already exhausted or aborted: only that may fail before step 0. */
  function exhausted(budget: Operation | undefined, signal?: AbortSignal): boolean {
    let aborted = false, expired = false;
    try { aborted = budget?.signal?.aborted === true || signal?.aborted === true; expired = Number.isFinite(budget?.deadline) && budget!.deadline <= Date.now(); }
    catch { /* A malformed budget is not exhausted. */ }
    return aborted || expired;
  }
  /** Step 0 at a public boundary, before any argument or target check. */
  async function retireAtBoundary(status: number | undefined, credential: DeliveryCredential | undefined, context: unknown,
    budget: Operation | undefined, signal?: AbortSignal): Promise<void> {
    if (status !== 401 || exhausted(budget, signal)) return;
    try { await retireFirst(status, credential, context); }
    catch (error) { throw classify(classifyAuthError(error, "provider_failed", signal)); }
  }
  /**
   * Step 0: drop the rejected access token (keeping refresh material) unless a newer
   * generation exists, under the commit budget, so it is never resent.
   */
  async function retire(owner: Attempt, operation: Operation): Promise<void> {
    const settle = commit();
    await race(operation.signal, store.coordinate(owner.key, settle.signal, async () => {
      const current = await read(owner.key, "grant", settle);
      if (current?.generation !== owner.generation || current.token === undefined) return;
      const { token: _token, expiresAt: _expiresAt, kind: _kind, generation: _generation, ...rest } = current;
      await saveGrant(owner.key, current.generation, rest, settle);
    }));
  }

  // ---- Dynamic registration -------------------------------------------------

  /** An initial access token is resolved by reference and sent only to this issuer's endpoint. */
  async function initialAccessToken(client: ClientConfig, operation: Operation): Promise<string | undefined> {
    const reference = client.registration!.initialAccessTokenRef;
    if (reference === undefined) return undefined;
    const token = secrets ? await race(operation.signal, secrets.get(reference, operation.signal)) : undefined;
    if (typeof token !== "string" || !token) throw new AuthError("credential_unavailable");
    return token;
  }
  /** PKCE: as in MCP clients, each login registers its own public client with its exact redirect. */
  async function registerLogin(target: ResolvedTarget, operation: Operation): Promise<string> {
    const metadata = target.metadata as unknown as Record<string, unknown>;
    const { method } = dcr(target.client, metadata, secrets !== undefined, true);
    const attempt = await register(metadata.registration_endpoint as string, registrationRequest(target.client, method!),
      await initialAccessToken(target.client, operation), target.client.flow, options, operation);
    if ("error" in attempt) throw attempt.error;
    return attempt.accepted.clientId;
  }
  /** Usable: not past a nonzero secret expiry, and its secret resolves. */
  async function resolveRecord(key: string, record: StoredRegistration, operation: Operation): Promise<Registered> {
    if (record.clientSecretExpiresAt && record.clientSecretExpiresAt * 1000 <= Date.now()) return { key, record, usable: false };
    if (!secrets) return { key, record, usable: false };
    const secret = await race(operation.signal, secrets.get(record.secretRef, operation.signal));
    return typeof secret === "string" && secret ? { key, record, secret, usable: true } : { key, record, usable: false };
  }
  /** Compare-and-delete a registration generation, then delete its secret reference. */
  async function dropGeneration(key: string, generation: string): Promise<void> {
    const settle = commit();
    const current = await read(key, "registration", settle);
    if (current?.generation !== generation || !await write(key, generation, undefined, settle)) return;
    await race(settle.signal, secrets!.delete(current.secretRef, settle.signal)).catch(() => {});
  }
  /** Advance the backoff by compare-and-set on its generation. */
  async function failed(key: string, prior: StoredRegistrationFailure | undefined, error: AuthError, retryAfterMs?: number): Promise<void> {
    const now = Date.now(), count = (prior?.attempts ?? 0) + 1;
    const backoff = Math.min(backoffInitial * 2 ** Math.min(count - 1, 52), backoffMax);
    const delay = Math.min(Math.max(backoff, retryAfterMs ?? 0), backoffMax);
    const value: StoredRegistrationFailure = { kind: "registration_failure", generation: crypto.randomUUID(),
      attempts: count, nextAttemptAt: now + delay, code: error.code };
    await write(failureKey(key), prior?.generation, value, commit());
  }
  /** A token request with the registered client succeeded: reset the failure count. */
  /**
   * A token request with the registered client succeeded: reset the failure count, but
   * only while that registration generation is still the stored one.
   */
  async function clearFailure(key: string, generation: string): Promise<void> {
    const settle = commit();
    try {
      const marker = await read(failureKey(key), "registration_failure", settle);
      if (!marker || (await read(key, "registration", settle))?.generation !== generation) return;
      await write(failureKey(key), marker.generation, undefined, settle);
    } catch { /* Best effort: the count is cleared by a later success. */ }
  }
  /** Store the secret under a fresh reference, then compare-and-set the record, under the commit budget. */
  async function save(key: string, current: StoredRegistration | undefined, accepted: AcceptedRegistration,
    method: AuthMethod): Promise<Registered> {
    const settle = commit();
    const secretRef = crypto.randomUUID();
    await race(settle.signal, secrets!.put(secretRef, accepted.clientSecret!, settle.signal));
    const record: StoredRegistration = { kind: "registration", generation: crypto.randomUUID(), clientId: accepted.clientId,
      tokenEndpointAuthMethod: method as StoredRegistration["tokenEndpointAuthMethod"], secretRef,
      ...(accepted.clientSecretExpiresAt === undefined ? {} : { clientSecretExpiresAt: accepted.clientSecretExpiresAt }) };
    let won = false;
    try {
      won = await write(key, current?.generation, record, settle);
    } finally {
      if (!won) await race(settle.signal, secrets!.delete(secretRef, settle.signal)).catch(() => {});
    }
    if (!won) {
      // Another process registered first: use its record.
      const winner = await read(key, "registration", settle);
      const resolved = winner ? await resolveRecord(key, winner, settle) : undefined;
      if (!resolved?.usable) throw new AuthError("provider_failed");
      return resolved;
    }
    if (current) await race(settle.signal, secrets!.delete(current.secretRef, settle.signal)).catch(() => {});
    return { key, record, secret: accepted.clientSecret!, usable: true };
  }
  /**
   * Client credentials, under the registration-key lock: reuse a usable record or
   * register once. After a failure only host `prepare` registers until the backoff passes.
   */
  function registration(target: ResolvedTarget, key: string, mode: Mode, operation: Operation, replace = false): Promise<Registered> {
    const { client } = target, metadata = target.metadata as unknown as Record<string, unknown>;
    return race(operation.signal, store.coordinate(key, operation.signal, async () => {
      const current = await read(key, "registration", operation);
      if (current && !replace) {
        const resolved = await resolveRecord(key, current, operation);
        if (resolved.usable) return resolved;
      }
      const markerKey = failureKey(key);
      const marker = await read(markerKey, "registration_failure", operation);
      if (marker && mode !== "host" && Date.now() < marker.nextAttemptAt) throw new AuthError(marker.code as AuthErrorCode);
      const { method } = dcr(client, metadata, secrets !== undefined, true);
      const attempt = await register(metadata.registration_endpoint as string, registrationRequest(client, method!),
        await initialAccessToken(client, operation), client.flow, options, operation);
      if ("error" in attempt) {
        await failed(key, marker, attempt.error, attempt.retryAfterMs);
        throw attempt.error;
      }
      const saved = await save(key, current, attempt.accepted, method!);
      // A success ends the backoff; the failure count survives until a token request with the
      // client succeeds, so a server that accepts registrations but rejects the clients keeps backing off.
      if (marker) {
        await write(markerKey, marker.generation, { ...marker, generation: crypto.randomUUID(), nextAttemptAt: 0 }, commit()).catch(() => false);
      }
      return saved;
    }));
  }
  function withRegistration(target: Selected, registered: Registered): Selected {
    const { clientSecret: _secret, clientId: _client, ...client } = target.client;
    const { record, secret } = registered;
    return { ...target, registration: registered,
      ...(record ? { authMethod: record.tokenEndpointAuthMethod } : {}),
      client: { ...client, ...(record ? { clientId: record.clientId } : {}), ...(secret === undefined ? {} : { clientSecret: secret }) } };
  }

  // ---- Client selection and bindings ----------------------------------------

  /**
   * Attach the client source: pre-registered, CIMD or DCR. A PKCE DCR client is issued
   * per login and refreshed from its grant; client credentials load their registration.
   */
  async function withClient(target: ResolvedTarget, recorded: ClientSelection | undefined, operation: Operation,
    redirect?: string): Promise<Selected> {
    const client = redirect === undefined ? target.client : { ...target.client, redirectUri: redirect };
    // The CIMD redirect is checked when a login is created; lookups and refreshes need none.
    const choice = chooseSource(client, target.metadata as unknown as Record<string, unknown>, secrets !== undefined, recorded, false);
    const selection: ClientSelection = choice.source === "dcr" ? { source: "dcr" } : { source: choice.source, clientId: choice.clientId! };
    const selected = { ...target, client, selection, identity: clientIdentity(selection) };
    if (choice.source === "preregistered") return selected;
    // CIMD and DCR PKCE clients are public: no secret is ever sent.
    const { clientSecret: _secret, ...rest } = client;
    if (choice.source === "cimd") return { ...selected, client: { ...rest, clientId: choice.clientId! } };
    if (client.flow === "authorization_code_pkce") return { ...selected, client: rest };
    const key = registrationKey(namespace, client.issuer);
    const current = await read(key, "registration", operation);
    return withRegistration(selected, current ? await resolveRecord(key, current, operation) : { key, usable: false });
  }
  /** Before a client-credentials token request: register where no usable registration exists. */
  async function usableClient(target: Selected, mode: Mode, operation: Operation): Promise<Selected> {
    const registered = target.registration;
    if (!registered || registered.usable) return target;
    return withRegistration(target, await registration(target, registered.key, mode, operation));
  }

  /** The recorded selection applies only to the issuer it was made for. */
  function recordedFor(cached: StoredBinding | undefined, target: ResolvedTarget): ClientSelection | undefined {
    return cached?.issuer === target.client.issuer ? cached.client : undefined;
  }
  /** Persist the binding, with its client selection, only when it changed. */
  async function saveBinding(context: DeliveryAuthContext, cached: StoredBinding | undefined, target: Selected, operation: Operation): Promise<void> {
    const value: StoredBinding = { kind: "binding", generation: crypto.randomUUID(), issuer: target.client.issuer,
      resource: target.client.resource, metadata: target.metadata, discoveredAt: Date.now(),
      grantKey: grantKey(namespace, context, target.client, target.identity), client: target.selection };
    // Write only on change; a lost race means another writer stored an equally fresh binding.
    const same = cached && cached.issuer === value.issuer && cached.resource === value.resource &&
      cached.grantKey === value.grantKey && JSON.stringify(cached.metadata) === JSON.stringify(value.metadata) &&
      JSON.stringify(cached.client) === JSON.stringify(value.client);
    if (!same) await write(bindingKey(namespace, context), cached?.generation, value, operation);
  }
  /** Discover over the network outside store locks, then select the client. */
  async function discoverBinding(context: DeliveryAuthContext, cached: StoredBinding | undefined, operation: Operation,
    staleFallback = true, redirect?: string, gate?: ScopeGate): Promise<Selected> {
    let target: ResolvedTarget;
    try {
      target = await resolveTarget(context, options, operation, undefined, gate);
    } catch (error) {
      operation.signal.throwIfAborted();
      // A metadata outage must not block refresh/acquisition with a known binding.
      if (!staleFallback || !cached || !(error instanceof AuthError) || error.code !== "discovery_failed" || gated.has(error)) throw error;
      const stale = await resolveTarget(context, options, operation, cached, gate);
      return withClient(stale, recordedFor(cached, stale), operation, redirect);
    }
    const selected = await withClient(target, recordedFor(cached, target), operation, redirect);
    await saveBinding(context, cached, selected, operation);
    return selected;
  }

  // ---- Acquisition ------------------------------------------------------------

  /**
   * The single path for host prepare, delivery credentials, the up-front lookup and
   * challenge handling: resolve the client, then act on `decide`'s outcome (section 2).
   * `sent` is the attempt whose token the challenged response rejected.
   */
  async function acquire(context: DeliveryAuthContext, operation: Operation, mode: Mode, explicit: readonly string[] = [],
    redirect?: string, forceRegistration = false, sent?: Attempt, op: DecisionOperation = mode === "host" ? "prepare" : "credential",
  ): Promise<PrepareResult | typeof LOOKUP_MISS> {
    const challenge = challengeOf(context);
    // Step 0: a 401 retires the rejected token before every target, configuration and
    // decide check, whatever the outcome.
    if (challenge.status === 401) {
      if (sent) await retire(sent, operation);
      else await retireFirst(401, context.rejectedCredential, context);
    }
    if (context.authentication !== undefined && context.authentication.type !== "oauth") throw new AuthError("unsupported_binding");
    if (!Array.isArray(explicit)) throw new AuthError("invalid_configuration");
    const binding = identity(context);
    const explicitScopes = Object.freeze([...explicit]);
    const preset = presetOf(context);
    sent ??= attemptOf(context.rejectedCredential, context);
    // Steps 1-4 decide locally once the client is selected, before any authorization-server I/O.
    const gate: ScopeGate = async (client, presetScopes) => {
      const decision = decide({ op, config: configOf(client, explicitScopes, presetScopes), challenge, sent: sent?.generation });
      if (decision.outcome.type === "fail" && decision.outcome.step <= 4) {
        gated.add(decision.outcome.error);
        throw decision.outcome.error;
      }
    };
    return resolveAndAct();

    async function resolveAndAct(): Promise<PrepareResult | typeof LOOKUP_MISS> {
      const cached = await read(bindingKey(namespace, context), "binding", operation);
      if (!cached && mode === "lookup") return LOOKUP_MISS;
      const challenged = context.challenged === true || context.challenge !== undefined;
      // Paths that may exchange can repair a binding whose cached resolution fails
      // (stored issuer gone or no longer trusted) through full discovery.
      const repairable = mode === "host" || (mode === "delivery" && challenged);
      // Handling a 401 rediscovers (honouring a resource_metadata hint) before deciding,
      // after the local decision on the known binding.
      const rebind = op === "challenge" && challenge.status === 401;
      let target: Selected;
      if (cached) {
        let resolved: ResolvedTarget | undefined;
        try {
          resolved = await resolveTarget(context, options, operation, cached, gate);
        } catch (error) {
          operation.signal.throwIfAborted();
          // Only a host selectClient rejection is a policy refusal; other errors propagate.
          if (mode === "lookup" && isPolicyRefusal(error)) return LOOKUP_MISS;
          // A local decision cannot be repaired by rediscovery, so it fails without network I/O.
          if (!repairable || !(error instanceof AuthError) || gated.has(error)) throw error;
        }
        target = resolved && !rebind ? await withClient(resolved, recordedFor(cached, resolved), operation, redirect)
          : await discoverBinding(context, cached, operation, rebind, redirect, gate);
      } else {
        target = await discoverBinding(context, undefined, operation, true, redirect, gate);
      }
      const key = grantKey(namespace, context, target.client, target.identity);
      if (mode === "host") await sweepPersisted(key, operation);
      // A known binding whose host policy now names another grant is not a store miss;
      // a changed client selection is not such a change.
      const reselected = cached?.client !== undefined &&
        (cached.client.source !== "preregistered" || target.selection.source !== "preregistered");
      if (mode === "lookup" && cached?.grantKey !== undefined && cached.grantKey !==
          grantKey(namespace, context, target.client, reselected ? clientIdentity(cached.client!) : target.identity)) {
        throw new AuthError("discovery_failed");
      }
      if (cached && JSON.stringify(cached.client) !== JSON.stringify(target.selection)) await saveBinding(context, cached, target, operation);
      // Host prepare may force a new client-credentials registration, and a token for it.
      const force = mode === "host" && forceRegistration && target.registration !== undefined;
      const sentGeneration = sent?.key === key ? sent.generation : undefined;
      const decideFor = (target: Selected, grant: StoredGrant | undefined) => decide({ op, challenge, sent: sentGeneration,
        config: configOf(target.client, explicitScopes, preset), grant: grantOf(grant, target, force) });
      // Cached tokens are served without metadata I/O, locks or writes.
      const observed = await read(key, "grant", operation);
      const first = decideFor(target, observed);
      if (first.outcome.type === "fail") throw first.outcome.error;
      if (first.outcome.type === "use") return ready(observed!, key, binding);
      // Full discovery only on a cache miss, host prepare or challenge handling; a
      // known binding otherwise renews from persisted metadata (or fails, never anonymous).
      if (cached && repairable && !rebind) target = await discoverBinding(context, cached, operation, true, redirect, gate);
      target = force && target.registration
        ? withRegistration(target, await registration(target, target.registration.key, mode, operation, true))
        : await usableClient(target, mode, operation);
      const renew = (target: Selected) => {
        const key = grantKey(namespace, context, target.client, target.identity);
        return race(operation.signal, store.coordinate(key, operation.signal, async (): Promise<PrepareResult> => {
          // Under the grant lock the stored generation may have moved on: decide again.
          const current = await read(key, "grant", operation);
          const decision = decideFor(target, current);
          const { outcome, required } = decision;
          const ceiling = ceilingOf(target.client);
          switch (outcome.type) {
            case "fail": throw outcome.error;
            case "use": return ready(current!, key, binding);
            case "refresh": {
              const refreshing = target.selection.source !== "dcr" ? target : { ...target, client: { ...target.client, clientId: current!.clientId! } };
              const saved = await refresh(key, current!, current!.scopes, refreshing, operation);
              const denied = coverage(required, saved.scopes, ceiling);
              if (denied) throw denied;
              return ready(saved, key, binding);
            }
            case "acquire": {
              const token = await acquireClientCredentials(requesting(target, current, outcome.request), options, operation);
              const saved = await saveGrant(key, current?.generation, token, commit());
              if (target.registration?.record) await clearFailure(target.registration.key, target.registration.record.generation);
              const denied = coverage(required, saved.scopes, ceiling);
              if (denied) throw denied;
              return ready(saved, key, binding);
            }
            case "login": return login(context, requesting(target, current, outcome.request), key, required, operation);
          }
        }));
      };
      // invalid_client: a CIMD client is misconfigured; a registered client-credentials
      // client is deleted and replaced at most once per operation.
      let replaced = false;
      const attempt = async (target: Selected): Promise<PrepareResult> => {
        try {
          return await renew(target);
        } catch (error) {
          if (!isInvalidClient(error)) throw error;
          if (target.selection.source === "cimd") throw new AuthError("invalid_configuration");
          const registered = target.registration;
          if (!registered?.record) throw error;
          await dropGeneration(registered.key, registered.record.generation);
          if (replaced) {
            // Registrations are accepted but the clients rejected: back off like a failed registration.
            const rejected = new AuthError("credential_unavailable");
            await race(operation.signal, store.coordinate(registered.key, operation.signal, async () =>
              failed(registered.key, await read(failureKey(registered.key), "registration_failure", operation), rejected)));
            throw rejected;
          }
          replaced = true;
          return attempt(withRegistration(target, await registration(target, registered.key, mode, operation)));
        }
      };
      try {
        return await attempt(target);
      } catch (error) {
        operation.signal.throwIfAborted();
        if (!cached || !isTransportFailure(error)) throw error;
      }
      // The token endpoint provably did not process the request (DNS, connect, TLS
      // handshake, 404/410): persisted metadata may be stale. Refetch the stored
      // issuer's metadata once, outside the lock, never protected-resource metadata.
      let refreshed: Selected;
      try {
        const resolved = await resolveTarget(context, options, operation, { issuer: cached.issuer, resource: cached.resource }, gate);
        refreshed = await withClient(resolved, recordedFor(cached, resolved), operation, redirect);
      } catch (error) {
        operation.signal.throwIfAborted();
        if (error instanceof AuthError && gated.has(error)) throw error;
        throw new AuthError("discovery_failed");
      }
      if (refreshed.client.issuer !== cached.issuer || grantKey(namespace, context, refreshed.client, refreshed.identity) !== key) {
        throw new AuthError("discovery_failed");
      }
      await write(bindingKey(namespace, context), cached.generation, { ...cached, generation: crypto.randomUUID(),
        metadata: refreshed.metadata, discoveredAt: Date.now() }, operation);
      return attempt(await usableClient(refreshed, mode, operation));
    }
  }

  /**
   * An acquisition requests `decide`'s set (previous ∪ ((S ∪ R [∪ P′]) ∩ C)) and records
   * response ∩ (previous ∪ acquisition ceiling), so a step-up never loses earlier scopes.
   */
  function requesting<T extends ResolvedTarget>(target: T, current: StoredGrant | undefined, request: readonly string[]): T {
    const ceiling = ceilingOf(target.client), previous = current?.scopes ?? [];
    return { ...target, client: { ...target.client, scopes: [...request], allowedScopes: [...new Set([...previous, ...ceiling])] } };
  }

  async function refresh(key: string, current: StoredGrant, prior: readonly string[], target: ResolvedTarget, operation: Operation): Promise<StoredGrant> {
    const presented = current.refreshToken!, client = current.clientId;
    let result: TokenResult;
    try {
      result = await refreshCredential(target, presented, prior, options, operation);
    } catch (error) {
      const rejected = error instanceof AuthError && error.code === "refresh_rejected";
      // A DCR client the server no longer knows: only fresh consent (and a new client) recovers.
      const unknownClient = client !== undefined && isInvalidClient(error);
      if (rejected || unknownClient) {
        // Compare-and-delete: a newer record (another refresh or login) is kept.
        const settle = commit();
        const latest = await read(key, "grant", settle);
        if (latest?.refreshToken === presented && latest.clientId === client) await write(key, latest.generation, undefined, settle);
      }
      operation.signal.throwIfAborted();
      // Like every token-endpoint failure, it carries no scopes.
      if (unknownClient) throw new AuthError("interaction_required");
      throw error;
    }
    if (!result.value) {
      // Not dispatched: keep a valid rotated refresh token, drop the unusable access token.
      const { token: _token, expiresAt: _expiresAt, kind: _kind, generation: _generation, ...rest } = current;
      if (result.refreshToken !== undefined) await saveGrant(key, current.generation, { ...rest, refreshToken: result.refreshToken }, commit());
      throw new AuthError("provider_failed");
    }
    const token: TokenValue = result.value;
    return saveGrant(key, current.generation, { ...token, refreshToken: token.refreshToken ?? presented,
      ...(client === undefined ? {} : { clientId: client }) }, commit());
  }

  // ---- Pending logins ---------------------------------------------------------

  function handle(record: StoredPendingLogin): PendingLogin {
    return Object.freeze({ type: "pending_login", authorizationUrl: record.authorizationUrl, expiresAt: record.expiresAt, state: record.state });
  }
  /** Delete expired process-owned logins. */
  function sweep(): void {
    const now = Date.now();
    for (const [state, record] of local) if (record.expiresAt <= now) local.delete(state);
  }
  /** Keep a login, cancelling the oldest beyond the cap for its grant key, atomically in a persisted store. */
  async function keep(record: StoredPendingLogin, operation: Operation): Promise<void> {
    if (!persist) {
      sweep();
      const same = [...local.values()].filter(other => other.grantKey === record.grantKey);
      for (const old of same.slice(0, Math.max(0, same.length - maxPending + 1))) local.delete(old.state);
      local.set(record.state, record);
      return;
    }
    const indexKey = pendingIndexKey(record.grantKey);
    await race(operation.signal, store.coordinate(indexKey, operation.signal, async () => {
      const index = await read(indexKey, "pending_index", operation);
      const live = await prune(index, operation);
      while (live.length >= maxPending) {
        const oldest = live.shift()!;
        await write(pendingKey(namespace, oldest.state), oldest.generation, undefined, operation);
      }
      if (!await write(pendingKey(namespace, record.state), undefined, record, operation)) throw new AuthError("provider_failed");
      const states = [...live.map(entry => entry.state), record.state];
      if (!await write(indexKey, index?.generation, { kind: "pending_index", generation: crypto.randomUUID(), states }, operation)) {
        await write(pendingKey(namespace, record.state), record.generation, undefined, commit()).catch(() => false);
        throw new AuthError("provider_failed");
      }
    }));
  }
  /** Delete expired logins named by a persisted index; returns the live ones, oldest first. Under the index lock. */
  async function prune(index: StoredPendingIndex | undefined, operation: Operation): Promise<{ state: string; generation: string }[]> {
    const live: { state: string; generation: string }[] = [];
    for (const state of index?.states ?? []) {
      const existing = await read(pendingKey(namespace, state), "pending_login", operation);
      if (existing && existing.expiresAt <= Date.now()) await write(pendingKey(namespace, state), existing.generation, undefined, operation);
      else if (existing) live.push({ state, generation: existing.generation });
    }
    return live;
  }
  /** Host prepare: delete a grant key's expired persisted logins, so an abandoned verifier does not linger. */
  async function sweepPersisted(grant: string, operation: Operation): Promise<void> {
    if (!persist) return;
    const indexKey = pendingIndexKey(grant);
    if (!await read(indexKey, "pending_index", operation)) return;
    await race(operation.signal, store.coordinate(indexKey, operation.signal, async () => {
      const index = await read(indexKey, "pending_index", operation);
      if (!index) return;
      const states = (await prune(index, operation)).map(entry => entry.state);
      if (states.length === index.states.length) return;
      await write(indexKey, index.generation, states.length ? { ...index, generation: crypto.randomUUID(), states } : undefined, operation);
    }));
  }
  async function find(state: string, operation: Operation): Promise<StoredPendingLogin | undefined> {
    if (!persist) {
      sweep();
      return local.get(state);
    }
    return read(pendingKey(namespace, state), "pending_login", operation);
  }
  /** End a login exactly once: false when it already ended. */
  async function claim(record: StoredPendingLogin, operation: Operation): Promise<boolean> {
    if (!persist) return local.get(record.state) === record && local.delete(record.state);
    if (!await write(pendingKey(namespace, record.state), record.generation, undefined, operation)) return false;
    // Best effort: creation also prunes ended logins from the index.
    const indexKey = pendingIndexKey(record.grantKey), settle = commit();
    await race(settle.signal, store.coordinate(indexKey, settle.signal, async () => {
      const index = await read(indexKey, "pending_index", settle);
      if (!index?.states.includes(record.state)) return;
      const states = index.states.filter(state => state !== record.state);
      await write(indexKey, index.generation, states.length ? { ...index, generation: crypto.randomUUID(), states } : undefined, settle);
    })).catch(() => {});
    return true;
  }

  /** Create a pending login for its own redirect and, with DCR, its own client. Host prepare only. */
  async function login(context: DeliveryAuthContext, target: Selected, key: string, required: readonly string[],
    operation: Operation): Promise<PendingLogin> {
    let client = target.client;
    if (target.selection.source === "cimd") cimdRedirect(client);
    if (target.selection.source === "dcr") {
      pkce(target);
      client = { ...client, clientId: await registerLogin(target, operation) };
    }
    // The stored ceiling bounds the grant recorded on completion.
    const started = await startLogin({ ...target, client }, options, operation);
    const { clientSecret: _secret, ...stored } = client;
    const record: StoredPendingLogin = {
      kind: "pending_login", generation: crypto.randomUUID(), state: started.state, grantKey: key,
      expiresAt: Date.now() + loginLifetime, authorizationUrl: started.authorizationUrl, verifier: started.verifier,
      client: stored, requiredScopes: [...required], metadata: target.metadata, context: durableContext(context), source: target.selection.source,
    };
    await keep(record, operation);
    return handle(record);
  }
  /**
   * The client a login completes with: current host client authentication for a
   * pre-registered client, else the login's own CIMD URL or issued DCR client, while
   * host policy still selects that source for the same grant key.
   */
  async function completionTarget(record: StoredPendingLogin, context: DeliveryAuthContext, operation: Operation): Promise<ResolvedTarget> {
    // complete() step 3, host policy only: client reselection; the login's stored R is checked after the claim.
    const reselected = await resolveTarget(context, options, operation,
      { issuer: record.client.issuer, resource: record.client.resource, metadata: record.metadata });
    const host = reselected.client;
    let client: ClientConfig = host, selection: ClientSelection;
    if (record.source === "preregistered") {
      if (host.clientId === undefined) throw new AuthError("invalid_configuration");
      selection = { source: "preregistered", clientId: host.clientId };
    } else {
      const { clientSecret: _secret, ...rest } = host;
      if (host.clientId !== undefined || (record.source === "cimd" ? host.clientMetadataDocument?.url !== record.client.clientId
        : !host.registration)) throw new AuthError("invalid_configuration");
      selection = record.source === "cimd" ? { source: "cimd", clientId: record.client.clientId! } : { source: "dcr" };
      client = { ...rest, clientId: record.client.clientId! };
    }
    if (grantKey(namespace, context, client, clientIdentity(selection)) !== record.grantKey) throw new AuthError("invalid_configuration");
    return { ...reselected, client: { ...client, redirectUri: record.client.redirectUri! } };
  }

  /** complete() step 3, host policy: the token endpoint's destination check, before the claim. */
  async function tokenDestination(target: ResolvedTarget, operation: Operation): Promise<void> {
    const endpoint = https(String(target.metadata.token_endpoint));
    const approved = endpoint.href;
    try {
      await options.checkDestination(endpoint, "token", operation);
    } catch (error) {
      active(operation);
      throw classifyAuthError(error, "untrusted_destination");
    }
    active(operation);
    if (endpoint.href !== approved) throw new AuthError("untrusted_destination");
  }

  // Successful host prepares (and completed logins) let Hooks re-attempt a backend
  // whose configuration discovery was skipped as unavailable.
  const preparedListeners = new Set<(endpoint: PreparedEndpoint) => void>();
  function prepared(context: Pick<DeliveryAuthContext, "backendId" | "purpose" | "url">): void {
    const endpoint: PreparedEndpoint = Object.freeze({ backendId: context.backendId, purpose: context.purpose, url: context.url });
    for (const listener of [...preparedListeners]) {
      try { listener(endpoint); } catch { /* A listener failure never fails the prepare. */ }
    }
  }

  async function prepare(input: DeliveryAuthContext, budget: Operation, prepareOptions: PrepareOptions = {}): Promise<PrepareResult> {
    // Snapshot synchronously, then step 0, then any argument or target failure.
    let context: DeliveryAuthContext, failure: unknown;
    try { context = snapshotContext(input); } catch (error) { failure = error; }
    if (statusOf(input) === 401 && input?.rejectedCredential) await retireAtBoundary(401, input.rejectedCredential, input, budget, input.signal);
    if (failure !== undefined) throw failure;
    context = context!;
    if (prepareOptions.requiredScopes !== undefined && !Array.isArray(prepareOptions.requiredScopes)) throw new AuthError("invalid_configuration");
    const explicit = [...(prepareOptions.requiredScopes ?? [])];
    const redirect = prepareOptions.redirectUri;
    const force = prepareOptions.forceRegistration;
    if ((redirect !== undefined && typeof redirect !== "string") || (force !== undefined && typeof force !== "boolean")) {
      throw new AuthError("invalid_configuration");
    }
    const result = await run(budget, context.signal,
      async operation => await acquire(context, operation, "host", explicit, redirect, force === true) as PrepareResult);
    if (result.type === "ready") prepared(context);
    return result;
  }

  /** Complete the pending login named by the callback's `state` (section 3). */
  async function complete(callback: string, budget: Operation): Promise<Ready> {
    let completed: DeliveryAuthContext | undefined;
    // Whether the named login no longer exists: "pending" until it is found ended or
    // claimed, "claiming" while the claim's outcome is uncertain.
    const progress: { phase: "pending" | "ended" | "claiming"; claimed?: StoredPendingLogin } = { phase: "pending" };
    let result: Ready;
    try {
      result = await run(budget, undefined, async (operation) => {
        if (typeof callback !== "string") throw new AuthError("invalid_configuration");
        // An unparseable callback is an invalid callback: it names no login and ends none.
        let state: string | null;
        try { state = new URL(callback).searchParams.get("state"); } catch { throw new AuthError("access_denied"); }
        // 1. Look the login up before any host callback runs.
        const record = state ? await find(state, operation) : undefined;
        if (!record || record.expiresAt <= Date.now()) {
          progress.phase = "ended";
          if (record) await claim(record, operation);
          throw new AuthError("interaction_required");
        }
        const stored: ResolvedTarget = { client: record.client as ClientConfig, metadata: record.metadata };
        const login = { authorizationUrl: record.authorizationUrl, state: record.state, verifier: record.verifier };
        // 2. Validate the callback; failures leave the login pending.
        let denied: boolean;
        try { denied = validateCallback(stored, login, callback); }
        catch { throw new AuthError("access_denied"); }
        // 3. Host policy (client selection, a client source no longer permitted) runs for
        // every valid callback, a consent denial included, before the claim.
        const context = snapshotContext(record.context as DeliveryAuthContext);
        const current = await completionTarget(record, context, operation);
        // ... and the token endpoint's destination policy, for every valid callback (a
        // denial included): a refusal keeps the host's code and the login pending.
        await tokenDestination(current, operation);
        // 4. Claim once; from here the login has ended.
        progress.phase = "claiming"; progress.claimed = record;
        const won = await claim(record, operation);
        progress.phase = "ended";
        if (!won) throw new AuthError("interaction_required");
        // 5. Consent denied.
        if (denied) {
          if (record.source === "cimd" && new URL(callback).searchParams.get("error") === "invalid_client") throw new AuthError("invalid_configuration");
          throw new AuthError("access_denied");
        }
        // 6. Exchange the code.
        const prior = (await read(record.grantKey, "grant", operation))?.scopes ?? [];
        const exchange: ResolvedTarget = { ...current, client: { ...current.client,
          scopes: record.client.scopes, allowedScopes: [...new Set([...prior, ...ceilingOf(record.client as ClientConfig)])] } };
        let result: TokenResult;
        try {
          result = await exchangeCode(exchange, login, callback, options, operation);
        } catch (error) {
          if (isInvalidClient(error) && record.source === "cimd") throw new AuthError("invalid_configuration");
          // A rejected DCR client ends only this login (the stored grant may hold an older
          // valid client); the next prepare registers again.
          if (isInvalidClient(error) && record.source === "dcr") throw new AuthError("interaction_required");
          throw error;
        }
        if (!result.value) throw new AuthError("provider_failed");
        // 7. Persist; the newest completed login wins. Then the stored R must be covered.
        const token = { ...result.value, ...(record.source === "dcr" ? { clientId: record.client.clientId! } : {}) };
        const settle = commit();
        const grant = await race(operation.signal, store.coordinate(record.grantKey, settle.signal, async () => {
          const latest = await read(record.grantKey, "grant", settle);
          return saveGrant(record.grantKey, latest?.generation, token, settle);
        }));
        // A record from an older release has no stored R: its prepare-time H, else the current H.
        const required = record.requiredScopes ?? record.client.requiredScopes ?? current.client.requiredScopes ?? [];
        const denial = coverage(required, grant.scopes, ceilingOf(current.client));
        if (denial) throw denial;
        const done: Ready = ready(grant, record.grantKey, identity(context));
        completed = context;
        return done;
      });
    } catch (error) {
      let ended = progress.phase === "ended";
      const claimed = progress.claimed;
      if (progress.phase === "claiming" && claimed) {
        // The claim's outcome is uncertain (store error, deadline): re-read on a fresh budget.
        const recheck: Operation = Object.freeze({ signal: AbortSignal.timeout(Math.min(commitTimeout, 5_000)), deadline: Date.now() + Math.min(commitTimeout, 5_000) });
        try { ended = (await find(claimed.state, recheck))?.generation !== claimed.generation; } catch { ended = false; }
      }
      throw loginEndedError(error, ended);
    }
    if (completed) prepared(completed);
    return result;
  }

  async function cancel(pending: PendingLogin, budget: Operation): Promise<void> {
    return run(budget, undefined, async (operation) => {
      if (!pending || typeof pending.state !== "string" || !pending.state) return;
      const record = await find(pending.state, operation);
      if (record) await claim(record, operation);
    });
  }

  async function challenge(input: AuthChallengeContext, budget: Operation): Promise<void> {
    const { response, credential } = input;
    // Only a 401 or 403 is a challenge.
    if (response.status !== 401 && response.status !== 403) return;
    const header = response.headers.get("www-authenticate") ?? undefined;
    const { rejectedCredential: _rejected, ...rest } = input;
    let context: DeliveryAuthContext, failure: unknown;
    try {
      context = snapshotContext({ ...rest, ...(header === undefined ? {} : { challenge: header }), challengeStatus: response.status, challenged: true });
    } catch (error) { failure = error; }
    if (response.status === 401 && credential) await retireAtBoundary(401, credential, input, budget, input.signal);
    if (failure !== undefined) throw failure;
    context = context!;
    return run(budget, context.signal, async (operation) => {
      // Prepare the next attempt (the replay, or the next notification/upload that is
      // never replayed): discovery, refresh and client-credentials acquisition, never a login.
      await acquire(context, operation, "delivery", [], undefined, false, attemptOf(credential, context), "challenge");
    });
  }

  function provider(host: { readonly budget: (context: DeliveryAuthContext) => Operation }): DeliveryAuthProvider {
    return {
      onPrepared(listener) {
        const subscription = (endpoint: PreparedEndpoint) => listener(endpoint);
        preparedListeners.add(subscription);
        return () => { preparedListeners.delete(subscription); };
      },
      async credential(input) {
        input?.signal?.throwIfAborted();
        // Snapshot synchronously; step 0 then precedes the host budget and every target check.
        let context: DeliveryAuthContext, failure: unknown;
        try { context = snapshotContext(input); } catch (error) { failure = error; }
        if (statusOf(input) === 401 && input?.rejectedCredential) await retireAtBoundary(401, input.rejectedCredential, input, undefined, input.signal);
        if (failure !== undefined) throw failure;
        context = context!;
        const lookup = context.authentication === undefined && !context.challenged && context.challenge === undefined;
        context.signal?.throwIfAborted();
        let budget: Operation;
        try { budget = host.budget(context); } catch (error) {
          context.signal?.throwIfAborted();
          // Without a budget an unbound endpoint with no stored binding still sends anonymously.
          let known: unknown;
          try { known = await store.load(bindingKey(namespace, context), context.signal ?? new AbortController().signal); }
          catch (failure) { throw classify(classifyAuthError(failure, "provider_failed", context.signal)); }
          if (lookup && known === undefined) return undefined;
          throw classify(classifyAuthError(error));
        }
        const result = await run(budget, context.signal, operation => acquire(context, operation, lookup ? "lookup" : "delivery"));
        // The up-front lookup is anonymous only on a store miss or a host policy refusal.
        if (result.type === "lookup_miss") return undefined;
        if (result.type !== "ready") throw new AuthError("interaction_required");
        return result.credential;
      },
      async challenge(input) {
        input.signal?.throwIfAborted();
        // Step 0 precedes the host budget and every target check.
        if (input.response?.status === 401 && input.credential) await retireAtBoundary(401, input.credential, input, undefined, input.signal);
        let budget: Operation;
        try { budget = host.budget(input); } catch (error) {
          input.signal?.throwIfAborted();
          throw classify(classifyAuthError(error));
        }
        return challenge(input, budget);
      },
    };
  }
  return Object.freeze({ prepare, complete, cancel, challenge, provider });
}
