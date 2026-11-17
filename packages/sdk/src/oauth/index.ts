import { AuthError, normalizeAuthTarget, classifyAuthError } from "../client/auth.js";
import type { AuthChallengeContext, DeliveryAuthContext, DeliveryAuthProvider, DeliveryCredential } from "../client/auth.js";
import { bearerParameters } from "../client/challenge.js";
import { isPolicyRefusal, resolveTarget, type CachedBinding } from "./discovery.js";
import { acquireClientCredentials, exchangeCode, isTransportFailure, refreshCredential, startLogin, validateCallback } from "./protocol.js";
import type { TokenResult } from "./protocol.js";
import type {
  ClientConfig, ManagedOAuthOptions, Operation, ResolvedTarget, StoredBinding, StoredGrant, StoredPendingLogin, StoredRecord, TokenValue,
} from "./types.js";
export type {
  ClientConfig, ManagedOAuthOptions, NetworkPurpose, Operation, PolicyFetch, StoredBinding, StoredGrant, StoredPendingLogin,
  StoredRecord, TokenStore, TokenValue,
} from "./types.js";

/**
 * Plain-data handle for a stored pending login. It may be serialized and passed to
 * `complete` or `cancel` in any process sharing the store. Keep it private: the
 * authorization URL carries OAuth state.
 */
export type PendingLogin = Readonly<{ type: "pending_login"; authorizationUrl: string; expiresAt: number; key: string; id: string }>;
/** `credential.token` is non-enumerable, so it is absent from JSON and inspection output. */
export type Ready = Readonly<{ type: "ready"; credential: DeliveryCredential }>;
export type PrepareResult = Ready | PendingLogin;
export interface PrepareOptions {
  /** Explicit operation requirements, such as `AuthError.requiredScopes` from a step-up challenge. */
  readonly requiredScopes?: readonly string[];
}

const MAX_LOGIN_LIFETIME = 600_000;
const EXPIRY_SKEW = 30_000;
const SCOPE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
type Mode = "host" | "delivery" | "lookup";
interface Attempt { readonly key: string; readonly generation: string; readonly identity: string }
/** Up-front lookup outcome for a store miss or host policy refusal: send anonymously. */
const LOOKUP_MISS = Object.freeze({ type: "lookup_miss" as const });

/** Canonical UTF-8 framed SDK storage identity. */
export function frame(prefix: string, fields: readonly string[]): string {
  const encoder = new TextEncoder();
  return prefix + fields.map(value => `${encoder.encode(value).length}:${value}`).join("");
}
export function bindingKey(namespace: string, context: DeliveryAuthContext): string {
  normalizeAuthTarget(context);
  return frame("ahp.oauth.binding:", [namespace, context.backendId, context.purpose, context.url]);
}
/** Grant identity: no ceiling, secrets, token-endpoint auth method or scope sets. */
export function grantKey(namespace: string, context: DeliveryAuthContext, client: ClientConfig): string {
  if (client.grantPartition !== undefined && (typeof client.grantPartition !== "string" || !client.grantPartition)) {
    throw new AuthError("invalid_configuration");
  }
  return frame("ahp.oauth.grant:", [namespace, client.issuer, client.resource, client.clientId, client.flow,
    client.grantPartition === undefined ? `binding:${bindingKey(namespace, context)}` : `shared:${client.grantPartition}`]);
}
function pendingKey(namespace: string, context: DeliveryAuthContext): string {
  return frame("ahp.oauth.pending:", [bindingKey(namespace, context)]);
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
      typeof configuration.selectClient !== "function") throw new AuthError("invalid_configuration");
  const options = { ...configuration };
  const { store, namespace } = options;
  const loginLifetime = options.loginLifetimeMs ?? MAX_LOGIN_LIFETIME;
  const commitTimeout = options.commitTimeoutMs ?? 30_000;
  if (!Number.isFinite(loginLifetime) || loginLifetime <= 0 || loginLifetime > MAX_LOGIN_LIFETIME ||
      !Number.isFinite(commitTimeout) || commitTimeout <= 0) throw new AuthError("invalid_configuration");
  /**
   * Persisting a token response is not tied to the caller's budget: the server has
   * already spent the old refresh token, so losing the rotated one would replay it.
   */
  const commit = (): Operation => Object.freeze({ signal: AbortSignal.timeout(Math.min(commitTimeout, 2_147_483_647)), deadline: Date.now() + commitTimeout });
  const attempts = new WeakMap<object, Attempt>();

  async function read<K extends StoredRecord["kind"]>(key: string, kind: K, operation: Operation): Promise<Extract<StoredRecord, { kind: K }> | undefined> {
    const value = await race(operation.signal, store.load(key, operation.signal));
    if (value === undefined) return undefined;
    if (typeof value !== "object" || value === null || value.kind !== kind || typeof value.generation !== "string" || !value.generation ||
        (kind === "grant" && (!Array.isArray((value as StoredGrant).scopes) ||
          ((value as StoredGrant).token !== undefined && typeof (value as StoredGrant).token !== "string") ||
          ((value as StoredGrant).expiresAt !== undefined && !Number.isFinite((value as StoredGrant).expiresAt))))) {
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

  /** Discover over the network outside store locks; persist the binding only when it changed. */
  async function discoverBinding(context: DeliveryAuthContext, cached: StoredBinding | undefined, operation: Operation,
    staleFallback = true): Promise<ResolvedTarget> {
    let target: ResolvedTarget;
    try {
      target = await resolveTarget(context, options, operation);
    } catch (error) {
      operation.signal.throwIfAborted();
      // A metadata outage must not block refresh/acquisition with a known binding.
      if (!staleFallback || !cached || !(error instanceof AuthError) || error.code !== "discovery_failed") throw error;
      return resolveTarget(context, options, operation, cached);
    }
    const value: StoredBinding = { kind: "binding", generation: crypto.randomUUID(), issuer: target.client.issuer,
      resource: target.client.resource, metadata: target.metadata, discoveredAt: Date.now(),
      grantKey: grantKey(namespace, context, target.client) };
    // Write only on change; a lost race means another writer stored an equally fresh binding.
    const same = cached && cached.issuer === value.issuer && cached.resource === value.resource &&
      cached.grantKey === value.grantKey && JSON.stringify(cached.metadata) === JSON.stringify(value.metadata);
    if (!same) await write(bindingKey(namespace, context), cached?.generation, value, operation);
    return target;
  }

  /** The single acquisition path for host prepare, delivery credentials and the up-front lookup. */
  async function acquire(context: DeliveryAuthContext, operation: Operation, mode: Mode, explicit: readonly string[] = []): Promise<PrepareResult | typeof LOOKUP_MISS> {
    if (context.authentication !== undefined && context.authentication.type !== "oauth") throw new AuthError("unsupported_binding");
    const binding = identity(context);
    const cached = await read(bindingKey(namespace, context), "binding", operation);
    if (!cached && mode === "lookup") return LOOKUP_MISS;
    const challenged = context.challenged === true || context.challenge !== undefined;
    // Paths that may exchange can repair a binding whose cached resolution fails
    // (stored issuer gone or no longer trusted) through full discovery.
    const repairable = mode === "host" || (mode === "delivery" && challenged);
    let target: ResolvedTarget;
    try {
      target = cached ? await resolveTarget(context, options, operation, cached) : await discoverBinding(context, undefined, operation);
    } catch (error) {
      operation.signal.throwIfAborted();
      // Only a host selectClient rejection is a policy refusal; other errors propagate.
      if (mode === "lookup" && isPolicyRefusal(error)) return LOOKUP_MISS;
      if (!cached || !repairable || !(error instanceof AuthError)) throw error;
      target = await discoverBinding(context, cached, operation, false);
    }
    const withExplicit = (resolved: ResolvedTarget): ResolvedTarget => {
      const required = [...new Set([...(resolved.client.requiredScopes ?? []), ...scopes(explicit)])];
      if (!within(required, ceilingOf(resolved.client))) throw new AuthError("access_denied", required);
      return { ...resolved, client: { ...resolved.client, requiredScopes: required } };
    };
    target = withExplicit(target);
    let key = grantKey(namespace, context, target.client);
    // A known binding whose host policy now names another grant is not a store miss.
    if (mode === "lookup" && cached?.grantKey !== undefined && cached.grantKey !== key) throw new AuthError("discovery_failed");
    // Cached tokens are served without metadata I/O, locks or writes.
    const observed = await read(key, "grant", operation);
    if (usable(observed, target, target.client.requiredScopes ?? [])) return ready(observed, key, binding, target, []);
    // Full discovery only on a cache miss, host prepare or challenge handling; a
    // known binding otherwise renews from persisted metadata (or fails, never anonymous).
    if (cached && repairable) {
      target = withExplicit(await discoverBinding(context, cached, operation));
      key = grantKey(namespace, context, target.client);
    }
    const required = target.client.requiredScopes ?? [];
    const renew = (target: ResolvedTarget) => race(operation.signal, store.coordinate(key, operation.signal, async (): Promise<PrepareResult> => {
      const current = await read(key, "grant", operation);
      if (usable(current, target, required)) return ready(current, key, binding, target, []);
      const prior = current ? effective(current, target) : [];
      if (target.client.flow === "client_credentials") {
        const token = await acquireClientCredentials(acquisition(target, current), options, operation);
        return ready(await saveGrant(key, current?.generation, token, commit()), key, binding, target, required);
      }
      // A refresh can never broaden a grant, so it only helps when the requirement is already covered.
      if (current?.refreshToken && within(required, prior)) {
        return ready(await refresh(key, current, current.scopes, target, operation), key, binding, target, required);
      }
      if (mode !== "host") throw new AuthError("interaction_required", required);
      return login(context, acquisition(target, current), key, operation);
    }));
    try {
      return await renew(target);
    } catch (error) {
      operation.signal.throwIfAborted();
      if (!cached || !isTransportFailure(error)) throw error;
    }
    // The token endpoint provably did not process the request (DNS, connect, TLS
    // handshake, 404/410): persisted metadata may be stale. Refetch the stored
    // issuer's metadata once, outside the lock, never protected-resource metadata.
    let refreshed: ResolvedTarget;
    try {
      refreshed = withExplicit(await resolveTarget(context, options, operation, { issuer: cached.issuer, resource: cached.resource }));
    } catch (error) {
      operation.signal.throwIfAborted();
      throw new AuthError("discovery_failed");
    }
    if (refreshed.client.issuer !== cached.issuer || grantKey(namespace, context, refreshed.client) !== key) throw new AuthError("discovery_failed");
    await write(bindingKey(namespace, context), cached.generation, { ...cached, generation: crypto.randomUUID(),
      metadata: refreshed.metadata, discoveredAt: Date.now() }, operation);
    return renew(refreshed);
  }

  /**
   * A new acquisition for an existing grant key requests previously granted ∪
   * ((requested ∪ required) ∩ ceiling) and records response ∩ (previously granted
   * ∪ acquisition ceiling), so a step-up never loses earlier scopes.
   */
  function acquisition(target: ResolvedTarget, current: StoredGrant | undefined): ResolvedTarget {
    const ceiling = ceilingOf(target.client), previous = current?.scopes ?? [];
    const wanted = [...target.client.scopes, ...(target.client.requiredScopes ?? [])].filter(scope => ceiling.includes(scope));
    return { ...target, client: { ...target.client,
      scopes: [...new Set([...previous, ...wanted])], allowedScopes: [...new Set([...previous, ...ceiling])] } };
  }

  async function refresh(key: string, current: StoredGrant, prior: readonly string[], target: ResolvedTarget, operation: Operation): Promise<StoredGrant> {
    const presented = current.refreshToken!;
    let result: TokenResult;
    try {
      result = await refreshCredential(target, presented, prior, options, operation);
    } catch (error) {
      if (error instanceof AuthError && error.code === "refresh_rejected") {
        // Compare-and-delete: a newer record (another refresh or login) is kept.
        const settle = commit();
        const latest = await read(key, "grant", settle);
        if (latest?.refreshToken === presented) await write(key, latest.generation, undefined, settle);
      }
      operation.signal.throwIfAborted();
      throw error;
    }
    if (!result.value) {
      // Not dispatched: keep a valid rotated refresh token, drop the unusable access token.
      const { token: _token, expiresAt: _expiresAt, kind: _kind, generation: _generation, ...rest } = current;
      if (result.refreshToken !== undefined) await saveGrant(key, current.generation, { ...rest, refreshToken: result.refreshToken }, commit());
      throw new AuthError("provider_failed");
    }
    const token: TokenValue = result.value;
    return saveGrant(key, current.generation, { ...token, refreshToken: token.refreshToken ?? presented }, commit());
  }

  /** Reuse or atomically supersede the binding's stored pending login. Host prepare only. */
  async function login(context: DeliveryAuthContext, target: ResolvedTarget, key: string, operation: Operation): Promise<PendingLogin> {
    const storeKey = pendingKey(namespace, context);
    const ceiling = ceilingOf(target.client);
    const wanted = target.client.scopes;
    const existing = await read(storeKey, "pending_login", operation);
    const live = existing && existing.expiresAt > Date.now() ? existing : undefined;
    if (live && live.grantKey === key && live.client.redirectUri === target.client.redirectUri &&
        within(wanted, live.client.scopes)) return handle(live, storeKey);
    // With the same grant key and redirect, superseding grows both the requested scopes
    // and the stored ceiling, so alternating callers converge. Otherwise start afresh.
    const merge = live && live.grantKey === key && live.client.redirectUri === target.client.redirectUri ? live : undefined;
    const requested = [...new Set([...(merge?.client.scopes ?? []), ...wanted])];
    const stored = [...new Set([...(merge ? ceilingOf(merge.client as ClientConfig) : []), ...ceiling])];
    const { clientSecret: _secret, ...client } = target.client;
    // The stored ceiling bounds the grant recorded on completion.
    const loginTarget = { ...target, client: { ...client, scopes: requested, allowedScopes: stored } };
    const started = await startLogin(loginTarget, options, operation);
    const record: StoredPendingLogin = {
      kind: "pending_login", generation: crypto.randomUUID(), id: crypto.randomUUID(), grantKey: key,
      expiresAt: Date.now() + loginLifetime, authorizationUrl: started.authorizationUrl,
      state: started.state, verifier: started.verifier, client: loginTarget.client, metadata: target.metadata,
      context: durableContext(context),
    };
    if (!await write(storeKey, existing?.generation, record, operation)) throw new AuthError("provider_failed");
    return handle(record, storeKey);
  }
  function handle(record: StoredPendingLogin, key: string): PendingLogin {
    return Object.freeze({ type: "pending_login", authorizationUrl: record.authorizationUrl, expiresAt: record.expiresAt, key, id: record.id });
  }

  async function prepare(input: DeliveryAuthContext, budget: Operation, prepareOptions: PrepareOptions = {}): Promise<PrepareResult> {
    const context = snapshotContext(input);
    const explicit = [...(prepareOptions.requiredScopes ?? [])];
    return run(budget, context.signal, async operation => await acquire(context, operation, "host", explicit) as PrepareResult);
  }

  async function complete(pending: PendingLogin, callback: string, budget: Operation): Promise<Ready> {
    return run(budget, undefined, async (operation) => {
      if (!pending || typeof pending.key !== "string" || typeof pending.id !== "string" ||
          !pending.key.startsWith("ahp.oauth.pending:")) throw new AuthError("invalid_configuration");
      const record = await read(pending.key, "pending_login", operation);
      // Completed, superseded, cancelled or expired.
      if (!record || record.id !== pending.id || record.expiresAt <= Date.now()) throw new AuthError("interaction_required");
      const stored: ResolvedTarget = { client: record.client as ClientConfig, metadata: record.metadata };
      const login = { authorizationUrl: record.authorizationUrl, state: record.state, verifier: record.verifier };
      // Validate redirect, state and issuer before anything can consume the login.
      let denied: boolean;
      try { denied = validateCallback(stored, login, callback); }
      catch { throw new AuthError("access_denied"); }
      // Consent fixes identity, not runtime client authentication: reselect current
      // host secrets outside coordination, before claiming the callback.
      const context = snapshotContext(record.context as DeliveryAuthContext);
      const current = denied ? stored
        : await resolveTarget(context, options, operation, { issuer: record.client.issuer, resource: record.client.resource, metadata: record.metadata });
      if (grantKey(namespace, context, current.client) !== record.grantKey || current.client.redirectUri !== record.client.redirectUri) {
        throw new AuthError("invalid_configuration");
      }
      // Claim once: a validated callback (including denial) ends the login.
      if (!await write(pending.key, record.generation, undefined, operation)) throw new AuthError("interaction_required");
      if (denied) throw new AuthError("access_denied");
      const prior = (await read(record.grantKey, "grant", operation))?.scopes ?? [];
      const exchange: ResolvedTarget = { ...current, client: { ...current.client,
        scopes: record.client.scopes, allowedScopes: [...new Set([...prior, ...ceilingOf(record.client as ClientConfig)])] } };
      const result = await exchangeCode(exchange, login, callback, options, operation);
      // An invalid initial exchange persists nothing.
      if (!result.value) throw new AuthError("provider_failed");
      const token = result.value;
      const settle = commit();
      const grant = await race(operation.signal, store.coordinate(record.grantKey, settle.signal, async () => {
        const latest = await read(record.grantKey, "grant", settle);
        return saveGrant(record.grantKey, latest?.generation, token, settle);
      }));
      return ready(grant, record.grantKey, identity(context), current, record.client.requiredScopes ?? []);
    });
  }

  async function cancel(pending: PendingLogin, budget: Operation): Promise<void> {
    return run(budget, undefined, async (operation) => {
      if (!pending || typeof pending.key !== "string" || !pending.key.startsWith("ahp.oauth.pending:")) return;
      const record = await read(pending.key, "pending_login", operation);
      if (record?.id === pending.id) await write(pending.key, record.generation, undefined, operation);
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
