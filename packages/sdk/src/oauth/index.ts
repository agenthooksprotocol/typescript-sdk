import { AuthError, normalizeAuthTarget, classifyAuthError } from "../client/auth.js";
import type { AuthChallengeContext, AuthErrorCode, DeliveryAuthContext, DeliveryAuthProvider, DeliveryCredential, PreparedEndpoint } from "../client/auth.js";
import { bearerParameters } from "../client/challenge.js";
import { isPolicyRefusal, resolveTarget } from "./discovery.js";
import {
  acquireClientCredentials, exchangeCode, isInvalidClient, isTransportFailure, pkce, refreshCredential, startLogin, validateCallback,
} from "./protocol.js";
import type { TokenResult } from "./protocol.js";
import { chooseSource, clientIdentity, dcr, failureKey, frame, register, registrationKey, registrationRequest } from "./registration.js";
import type { AcceptedRegistration, AuthMethod } from "./registration.js";
import type {
  ClientConfig, ClientSelection, ManagedOAuthOptions, Operation, ResolvedTarget, StoredBinding, StoredGrant, StoredPendingLogin,
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
}

const MAX_LOGIN_LIFETIME = 600_000;
const EXPIRY_SKEW = 30_000;
const SCOPE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
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
function scopes(values: readonly string[]): string[] {
  if (!Array.isArray(values) || values.some(value => typeof value !== "string" || !SCOPE.test(value))) {
    throw new AuthError("invalid_configuration");
  }
  return [...new Set(values)].sort();
}
const ceilingOf = (client: ClientConfig) => client.allowedScopes ?? client.scopes;
const within = (values: readonly string[], set: readonly string[]) => values.every(value => set.includes(value));
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
    throw classifyAuthError(error, "provider_failed", signal);
  }
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
  function usable(grant: StoredGrant | undefined, target: ResolvedTarget, required: readonly string[]): grant is StoredGrant & { token: string } {
    return grant?.token !== undefined && (grant.expiresAt === undefined || grant.expiresAt > Date.now() + EXPIRY_SKEW) &&
      within(required, effective(grant, target));
  }
  function effective(grant: StoredGrant, target: ResolvedTarget): string[] {
    const ceiling = ceilingOf(target.client);
    return grant.scopes.filter(scope => ceiling.includes(scope));
  }
  function ready(grant: StoredGrant, key: string, binding: string, target: ResolvedTarget, required: readonly string[]): Ready {
    if (!within(required, effective(grant, target))) throw new AuthError("access_denied", required);
    if (!grant.token || !/^[A-Za-z0-9\-._~+/]+=*$/.test(grant.token)) throw new AuthError("credential_unavailable");
    const attempt = Object.freeze({});
    attempts.set(attempt, { key, generation: grant.generation, identity: binding });
    const credential = { type: "bearer" as const, attempt };
    Object.defineProperty(credential, "token", { value: grant.token, enumerable: false });
    return Object.freeze({ type: "ready", credential: Object.freeze(credential as DeliveryCredential) });
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
  function registration(target: ResolvedTarget, key: string, mode: Mode, operation: Operation): Promise<Registered> {
    const { client } = target, metadata = target.metadata as unknown as Record<string, unknown>;
    return race(operation.signal, store.coordinate(key, operation.signal, async () => {
      const current = await read(key, "registration", operation);
      if (current) {
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
      if (marker) await write(markerKey, marker.generation, undefined, commit()).catch(() => false);
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
    const choice = chooseSource(client, target.metadata as unknown as Record<string, unknown>, secrets !== undefined, recorded);
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
    staleFallback = true, redirect?: string): Promise<Selected> {
    let target: ResolvedTarget;
    try {
      target = await resolveTarget(context, options, operation);
    } catch (error) {
      operation.signal.throwIfAborted();
      // A metadata outage must not block refresh/acquisition with a known binding.
      if (!staleFallback || !cached || !(error instanceof AuthError) || error.code !== "discovery_failed") throw error;
      const stale = await resolveTarget(context, options, operation, cached);
      return withClient(stale, recordedFor(cached, stale), operation, redirect);
    }
    const selected = await withClient(target, recordedFor(cached, target), operation, redirect);
    await saveBinding(context, cached, selected, operation);
    return selected;
  }

  // ---- Acquisition ------------------------------------------------------------

  /** The single acquisition path for host prepare, delivery credentials and the up-front lookup. */
  async function acquire(context: DeliveryAuthContext, operation: Operation, mode: Mode, explicit: readonly string[] = [],
    redirect?: string): Promise<PrepareResult | typeof LOOKUP_MISS> {
    if (context.authentication !== undefined && context.authentication.type !== "oauth") throw new AuthError("unsupported_binding");
    const binding = identity(context);
    const cached = await read(bindingKey(namespace, context), "binding", operation);
    if (!cached && mode === "lookup") return LOOKUP_MISS;
    const challenged = context.challenged === true || context.challenge !== undefined;
    // Paths that may exchange can repair a binding whose cached resolution fails
    // (stored issuer gone or no longer trusted) through full discovery.
    const repairable = mode === "host" || (mode === "delivery" && challenged);
    let target: Selected;
    if (cached) {
      let resolved: ResolvedTarget | undefined;
      try {
        resolved = await resolveTarget(context, options, operation, cached);
      } catch (error) {
        operation.signal.throwIfAborted();
        // Only a host selectClient rejection is a policy refusal; other errors propagate.
        if (mode === "lookup" && isPolicyRefusal(error)) return LOOKUP_MISS;
        if (!repairable || !(error instanceof AuthError)) throw error;
      }
      target = resolved ? await withClient(resolved, recordedFor(cached, resolved), operation, redirect)
        : await discoverBinding(context, cached, operation, false, redirect);
    } else {
      target = await discoverBinding(context, undefined, operation, true, redirect);
    }
    const withExplicit = <T extends ResolvedTarget>(resolved: T): T => {
      const required = [...new Set([...(resolved.client.requiredScopes ?? []), ...scopes(explicit)])];
      if (!within(required, ceilingOf(resolved.client))) throw new AuthError("access_denied", required);
      return { ...resolved, client: { ...resolved.client, requiredScopes: required } };
    };
    target = withExplicit(target);
    const key = grantKey(namespace, context, target.client, target.identity);
    // A known binding whose host policy now names another grant is not a store miss;
    // a changed client selection is not such a change.
    const reselected = cached?.client !== undefined &&
      (cached.client.source !== "preregistered" || target.selection.source !== "preregistered");
    if (mode === "lookup" && cached?.grantKey !== undefined && cached.grantKey !==
        grantKey(namespace, context, target.client, reselected ? clientIdentity(cached.client!) : target.identity)) {
      throw new AuthError("discovery_failed");
    }
    if (cached && JSON.stringify(cached.client) !== JSON.stringify(target.selection)) await saveBinding(context, cached, target, operation);
    // Cached tokens are served without metadata I/O, locks or writes.
    const observed = await read(key, "grant", operation);
    if (usable(observed, target, target.client.requiredScopes ?? [])) return ready(observed, key, binding, target, []);
    // Full discovery only on a cache miss, host prepare or challenge handling; a
    // known binding otherwise renews from persisted metadata (or fails, never anonymous).
    if (cached && repairable) target = withExplicit(await discoverBinding(context, cached, operation, true, redirect));
    target = await usableClient(target, mode, operation);
    const required = target.client.requiredScopes ?? [];
    const renew = (target: Selected) => {
      const key = grantKey(namespace, context, target.client, target.identity);
      return race(operation.signal, store.coordinate(key, operation.signal, async (): Promise<PrepareResult> => {
        const current = await read(key, "grant", operation);
        if (usable(current, target, required)) return ready(current, key, binding, target, []);
        const prior = current ? effective(current, target) : [];
        if (target.client.flow === "client_credentials") {
          const token = await acquireClientCredentials(acquisition(target, current), options, operation);
          return ready(await saveGrant(key, current?.generation, token, commit()), key, binding, target, required);
        }
        // A DCR grant refreshes with the client issued to the login that produced it.
        const refreshing = target.selection.source !== "dcr" ? target
          : current?.clientId === undefined ? undefined : { ...target, client: { ...target.client, clientId: current.clientId } };
        // A refresh can never broaden a grant, so it only helps when the requirement is already covered.
        if (current?.refreshToken && refreshing && within(required, prior)) {
          return ready(await refresh(key, current, current.scopes, refreshing, operation), key, binding, target, required);
        }
        if (mode !== "host") throw new AuthError("interaction_required", required);
        return login(context, acquisition(target, current), key, operation);
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
        if (replaced) throw new AuthError("credential_unavailable");
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
      const resolved = await resolveTarget(context, options, operation, { issuer: cached.issuer, resource: cached.resource });
      refreshed = withExplicit(await withClient(resolved, recordedFor(cached, resolved), operation, redirect));
    } catch (error) {
      operation.signal.throwIfAborted();
      throw new AuthError("discovery_failed");
    }
    if (refreshed.client.issuer !== cached.issuer || grantKey(namespace, context, refreshed.client, refreshed.identity) !== key) {
      throw new AuthError("discovery_failed");
    }
    await write(bindingKey(namespace, context), cached.generation, { ...cached, generation: crypto.randomUUID(),
      metadata: refreshed.metadata, discoveredAt: Date.now() }, operation);
    return attempt(await usableClient(refreshed, mode, operation));
  }

  /**
   * A new acquisition for an existing grant key requests previously granted ∪
   * ((requested ∪ required) ∩ ceiling) and records response ∩ (previously granted
   * ∪ acquisition ceiling), so a step-up never loses earlier scopes.
   */
  function acquisition<T extends ResolvedTarget>(target: T, current: StoredGrant | undefined): T {
    const ceiling = ceilingOf(target.client), previous = current?.scopes ?? [];
    const wanted = [...target.client.scopes, ...(target.client.requiredScopes ?? [])].filter(scope => ceiling.includes(scope));
    return { ...target, client: { ...target.client,
      scopes: [...new Set([...previous, ...wanted])], allowedScopes: [...new Set([...previous, ...ceiling])] } };
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
      if (unknownClient) throw new AuthError("interaction_required", target.client.requiredScopes);
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
      const live: { state: string; generation: string }[] = [];
      for (const state of index?.states ?? []) {
        const existing = await read(pendingKey(namespace, state), "pending_login", operation);
        if (existing && existing.expiresAt <= Date.now()) await write(pendingKey(namespace, state), existing.generation, undefined, operation);
        else if (existing) live.push({ state, generation: existing.generation });
      }
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
  async function login(context: DeliveryAuthContext, target: Selected, key: string, operation: Operation): Promise<PendingLogin> {
    let client = target.client;
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
      client: stored, metadata: target.metadata, context: durableContext(context), source: target.selection.source,
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
    const context = snapshotContext(input);
    const explicit = [...(prepareOptions.requiredScopes ?? [])];
    const redirect = prepareOptions.redirectUri;
    if (redirect !== undefined && typeof redirect !== "string") throw new AuthError("invalid_configuration");
    const result = await run(budget, context.signal, async operation => await acquire(context, operation, "host", explicit, redirect) as PrepareResult);
    if (result.type === "ready") prepared(context);
    return result;
  }

  /** Complete the pending login named by the callback's `state`. */
  async function complete(callback: string, budget: Operation): Promise<Ready> {
    let completed: DeliveryAuthContext | undefined;
    const result: Ready = await run(budget, undefined, async (operation) => {
      if (typeof callback !== "string") throw new AuthError("invalid_configuration");
      let state: string | null;
      try { state = new URL(callback).searchParams.get("state"); } catch { throw new AuthError("access_denied"); }
      const record = state ? await find(state, operation) : undefined;
      // Completed, cancelled, evicted, expired or owned by another process.
      if (!record) throw new AuthError("interaction_required");
      if (record.expiresAt <= Date.now()) {
        await claim(record, operation);
        throw new AuthError("interaction_required");
      }
      const stored: ResolvedTarget = { client: record.client as ClientConfig, metadata: record.metadata };
      const login = { authorizationUrl: record.authorizationUrl, state: record.state, verifier: record.verifier };
      // Validate redirect, state and issuer before anything can consume the login.
      let denied: boolean;
      try { denied = validateCallback(stored, login, callback); }
      catch { throw new AuthError("access_denied"); }
      // Consent fixes identity, not runtime client authentication: reselect current
      // host secrets outside coordination, before claiming the callback.
      const context = snapshotContext(record.context as DeliveryAuthContext);
      const current = denied ? stored : await completionTarget(record, context, operation);
      // Claim once: a validated callback (including denial) ends the login.
      if (!await claim(record, operation)) throw new AuthError("interaction_required");
      if (denied) {
        // An authorization endpoint invalid_client for a CIMD client is misconfiguration.
        if (record.source === "cimd" && new URL(callback).searchParams.get("error") === "invalid_client") throw new AuthError("invalid_configuration");
        throw new AuthError("access_denied");
      }
      const prior = (await read(record.grantKey, "grant", operation))?.scopes ?? [];
      const exchange: ResolvedTarget = { ...current, client: { ...current.client,
        scopes: record.client.scopes, allowedScopes: [...new Set([...prior, ...ceilingOf(record.client as ClientConfig)])] } };
      let result: TokenResult;
      try {
        result = await exchangeCode(exchange, login, callback, options, operation);
      } catch (error) {
        if (isInvalidClient(error) && record.source === "cimd") throw new AuthError("invalid_configuration");
        // A rejected DCR client ends only this login: the stored grant may hold an older valid client.
        if (isInvalidClient(error) && record.source === "dcr") throw new AuthError("interaction_required", record.client.requiredScopes);
        throw error;
      }
      // An invalid initial exchange persists nothing.
      if (!result.value) throw new AuthError("provider_failed");
      // The issued client is committed with its tokens; the newest completed login wins.
      const token = { ...result.value, ...(record.source === "dcr" ? { clientId: record.client.clientId! } : {}) };
      const settle = commit();
      const grant = await race(operation.signal, store.coordinate(record.grantKey, settle.signal, async () => {
        const latest = await read(record.grantKey, "grant", settle);
        return saveGrant(record.grantKey, latest?.generation, token, settle);
      }));
      const done: Ready = ready(grant, record.grantKey, identity(context), current, record.client.requiredScopes ?? []);
      completed = context;
      return done;
    });
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
    const header = response.headers.get("www-authenticate") ?? undefined;
    const context = snapshotContext({ ...input, ...(header === undefined ? {} : { challenge: header }), challenged: true });
    return run(budget, context.signal, async (operation) => {
      const parameters = bearerParameters(header);
      const insufficient = response.status === 403 && parameters.get("error") === "insufficient_scope";
      if (response.status === 403 && !insufficient) throw new AuthError("access_denied");
      if (response.status !== 401 && !insufficient) return;
      const owner = credential ? attempts.get(credential.attempt as object) : undefined;
      if (credential && (!owner || owner.identity !== identity(context))) throw new AuthError("invalid_configuration");
      if (!insufficient && owner) {
        // Drop the rejected access token first (keeping refresh material) unless a newer
        // generation exists, under the commit budget: a later discovery failure or caller
        // abort must not leave the revoked token stored and resent.
        const settle = commit();
        await race(operation.signal, store.coordinate(owner.key, settle.signal, async () => {
          const current = await read(owner.key, "grant", settle);
          if (current?.generation !== owner.generation || current.token === undefined) return;
          const { token: _token, expiresAt: _expiresAt, kind: _kind, generation: _generation, ...rest } = current;
          await saveGrant(owner.key, current.generation, rest, settle);
        }));
      }
      const cached = await read(bindingKey(namespace, context), "binding", operation);
      // Challenge handling runs full discovery, honouring a resource_metadata hint.
      const target = await discoverBinding(context, cached, operation);
      if (insufficient) {
        // Operation-scoped: validated against the ceiling, never persisted. The replay
        // carries the same challenge, so its acquisition sees the same requirement.
        const advertised = parameters.get("scope");
        const required = advertised === undefined ? scopes(target.hostRequiredScopes ?? []) : scopes(advertised.split(" "));
        if (required.length === 0) throw new AuthError("access_denied");
        if (!within(required, ceilingOf(target.client))) throw new AuthError("access_denied", required);
        if (target.client.flow === "authorization_code_pkce") throw new AuthError("interaction_required", required);
      }
      // Prepare the next attempt (the replay, or the next notification/upload that is
      // never replayed): discovery and client-credentials acquisition, never a login.
      // A rejected token is stale even with unknown or future expiry: renew it now
      // (refresh or client credentials) so it is never resent.
      const grant = owner ? await read(owner.key, "grant", operation) : undefined;
      if (target.client.flow === "client_credentials" || grant?.refreshToken) await acquire(context, operation, "delivery");
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
        const context = snapshotContext(input);
        const lookup = context.authentication === undefined && !context.challenged && context.challenge === undefined;
        context.signal?.throwIfAborted();
        let budget: Operation;
        try { budget = host.budget(context); } catch (error) {
          context.signal?.throwIfAborted();
          // Without a budget an unbound endpoint with no stored binding still sends anonymously.
          let known: unknown;
          try { known = await store.load(bindingKey(namespace, context), context.signal ?? new AbortController().signal); }
          catch (failure) { throw classifyAuthError(failure, "provider_failed", context.signal); }
          if (lookup && known === undefined) return undefined;
          throw classifyAuthError(error);
        }
        const result = await run(budget, context.signal, operation => acquire(context, operation, lookup ? "lookup" : "delivery"));
        // The up-front lookup is anonymous only on a store miss or a host policy refusal.
        if (result.type === "lookup_miss") return undefined;
        if (result.type !== "ready") throw new AuthError("interaction_required");
        return result.credential;
      },
      async challenge(input) {
        input.signal?.throwIfAborted();
        let budget: Operation;
        try { budget = host.budget(input); } catch (error) {
          input.signal?.throwIfAborted();
          throw classifyAuthError(error);
        }
        return challenge(input, budget);
      },
    };
  }
  return Object.freeze({ prepare, complete, cancel, challenge, provider });
}
