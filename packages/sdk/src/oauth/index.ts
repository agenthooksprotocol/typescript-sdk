import { AuthError, normalizeAuthTarget, classifyAuthError } from "../client/auth.js";
import type { AuthChallengeContext, DeliveryAuthContext, DeliveryAuthProvider, DeliveryCredential } from "../client/auth.js";
import { resolveTarget, bearerParameters } from "./discovery.js";
import { acquireClientCredentials, exchangeCode, refreshCredential, startLogin, validateCallback } from "./protocol.js";
import type { LoginState } from "./protocol.js";
import type { ManagedOAuthOptions, Operation, ResolvedTarget, StoredCredential, TokenValue } from "./types.js";
export type { ClientConfig, ManagedOAuthOptions, NetworkPurpose, Operation, PolicyFetch, StoredCredential, TokenStore, TokenValue } from "./types.js";

export type PendingLogin = Readonly<{ type: "pending_login"; authorizationUrl: string; expiresAt: number }>;
export type Ready = Readonly<{ type: "ready"; credential: DeliveryCredential }>;
export type PrepareResult = Ready | PendingLogin;
interface PendingRecord {
  readonly key: string;
  readonly target: ResolvedTarget;
  readonly identity: string;
  readonly baseGeneration: string | undefined;
  readonly expiresAt: number;
  readonly signals: readonly AbortSignal[];
  login?: LoginState;
  pending?: PendingLogin;
  cleanup?: () => void;
}
interface Attempt { readonly key: string; readonly generation: string; readonly identity: string }

function identity(context: DeliveryAuthContext): string {
  const target = normalizeAuthTarget(context);
  return frame("ahp.oauth.binding:", ["", target.backendId, target.purpose, target.url]);
}
/** Canonical UTF-8 framed SDK storage identity. */
export function frame(prefix: string, fields: readonly string[]): string {
  const encoder = new TextEncoder();
  return prefix + fields.map(value => `${encoder.encode(value).length}:${value}`).join("");
}
export function bindingKey(namespace: string, context: DeliveryAuthContext): string {
  normalizeAuthTarget(context);
  return frame("ahp.oauth.binding:", [namespace, context.backendId, context.purpose, context.url]);
}
function scopes(values: readonly string[]): string[] {
  if (!Array.isArray(values) || values.some(value => typeof value !== "string" ||
      !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(value))) throw new AuthError("invalid_configuration");
  return [...new Set(values)].sort();
}
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
export function grantKey(namespace: string, context: DeliveryAuthContext, client: import("./types.js").ClientConfig): string {
  if (client.grantPartition !== undefined && (typeof client.grantPartition !== "string" || !client.grantPartition)) {
    throw new AuthError("invalid_configuration");
  }
  return frame("ahp.oauth.grant:", [namespace, client.issuer, client.resource, client.clientId,
    client.flow, scopes(client.allowedScopes ?? client.scopes).join(" "),
    client.grantPartition === undefined ? `binding:${bindingKey(namespace, context)}` : `shared:${client.grantPartition}`]);
}
async function step<T>(operation: Operation, work: Promise<T>): Promise<T> {
  const signal = operation.signal;
  let abort: (() => void) | undefined;
  try {
    const cancelled = new Promise<never>((_, reject) => {
      abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    });
    const value = await Promise.race([work, cancelled]);
    signal.throwIfAborted();
    return value;
  } finally { if (abort) signal.removeEventListener("abort", abort); }
}
async function bounded<T>(input: Operation, work: (operation: Operation) => Promise<T>, upstream: readonly AbortSignal[] = []): Promise<T> {
  const budget = Object.freeze({ signal: input.signal, deadline: input.deadline });
  if (!budget.signal || typeof budget.signal.throwIfAborted !== "function") throw new AuthError("invalid_configuration");
  budget.signal.throwIfAborted();
  if (!Number.isFinite(budget.deadline)) throw new AuthError("invalid_configuration");
  const remaining = budget.deadline - Date.now();
  if (remaining <= 0) throw new DOMException("Operation deadline exceeded", "TimeoutError");
  const controller = new AbortController();
  const sources = [...new Set([budget.signal, ...upstream])];
  for (const signal of sources) signal.throwIfAborted();
  const listeners = sources.map(signal => {
    const abort = () => controller.abort(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    return { signal, abort };
  });
  const timer = setTimeout(() => controller.abort(new DOMException("Operation deadline exceeded", "TimeoutError")), Math.min(remaining, 2_147_483_647));
  const operation = Object.freeze({ signal: controller.signal, deadline: budget.deadline });
  try {
    return await step(operation, Promise.resolve().then(() => {
      operation.signal.throwIfAborted();
      return work(operation);
    }));
  } catch (error) {
    for (const signal of sources) signal.throwIfAborted();
    operation.signal.throwIfAborted();
    throw classifyAuthError(error);
  } finally {
    clearTimeout(timer);
    for (const { signal, abort } of listeners) signal.removeEventListener("abort", abort);
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
  const store = options.store;
  const pendingByKey = new Map<string, PendingRecord>();
  const pendingRecords = new WeakMap<PendingLogin, PendingRecord>();
  const attempts = new WeakMap<object, Attempt>();
  const ended = new WeakMap<PendingLogin, { readonly expiresAt: number; readonly signal: AbortSignal | undefined }>();
  function forget(record: PendingRecord): void {
    record.cleanup?.();
    if (record.pending) pendingRecords.delete(record.pending);
    if (pendingByKey.get(record.key) === record) pendingByKey.delete(record.key);
  }
  function retire(record: PendingRecord): void {
    if (record.pending) ended.set(record.pending, {
      expiresAt: record.expiresAt, signal: record.signals.find(signal => signal.aborted),
    });
    forget(record);
  }
  function retain(record: PendingRecord): void {
    const expire = () => retire(record);
    record.cleanup = () => {
      for (const signal of record.signals) signal.removeEventListener("abort", expire);
    };
    for (const signal of record.signals) signal.addEventListener("abort", expire, { once: true });
    if (record.signals.some(signal => signal.aborted)) expire();
  }
  function ready(value: StoredCredential, key: string, binding: string): Ready {
    if (!/^[A-Za-z0-9\-._~+/]+=*$/.test(value.token) || (value.expiresAt !== undefined && (!Number.isFinite(value.expiresAt) || value.expiresAt <= Date.now())) || !value.generation) throw new AuthError("credential_unavailable");
    const attempt = Object.freeze({});
    attempts.set(attempt, { key, generation: value.generation, identity: binding });
    return Object.freeze({ type: "ready", credential: Object.freeze({ type: "bearer", token: value.token, attempt }) });
  }
  function reusable(value: StoredCredential | undefined): value is StoredCredential {
    return value !== undefined && !value.rejected && (value.expiresAt === undefined || value.expiresAt > Date.now() + 30_000);
  }
  async function load(key: string, operation: Operation): Promise<StoredCredential | undefined> {
    const value = await step(operation, store.load(key, operation.signal));
    if (value === undefined) return undefined;
    if (!Array.isArray(value.scopes) || typeof value.generation !== "string" || !value.generation ||
        typeof value.token !== "string" || (value.expiresAt !== undefined && !Number.isFinite(value.expiresAt))) {
      throw new AuthError("credential_unavailable");
    }
    return Object.freeze({ ...value, scopes: Object.freeze([...value.scopes]) });
  }
  async function save(key: string, expected: string | undefined, token: TokenValue & { refreshQuarantined?: boolean }, operation: Operation) {
    operation.signal.throwIfAborted();
    const value: StoredCredential = Object.freeze({ ...token, scopes: Object.freeze([...token.scopes]), generation: crypto.randomUUID() });
    const saved = await step(operation, store.compareAndSet(key, expected, value, operation.signal));
    if (!saved) throw new AuthError("provider_failed");
    return value;
  }
  async function targetFor(context: DeliveryAuthContext, operation: Operation, force = false): Promise<ResolvedTarget> {
    if (context.authentication !== undefined && context.authentication.type !== "oauth") throw new AuthError("unsupported_binding");
    const cacheKey = bindingKey(options.namespace, context);
    const cached = await step(operation, store.load(cacheKey, operation.signal));
    if (!force && cached?.bindingMetadata) {
      try {
        return withBindingRequirements(await step(operation, resolveTarget(context, options, operation, structuredClone(cached.bindingMetadata))), cached.requiredScopes ?? []);
      } catch (error) {
        operation.signal.throwIfAborted();
        if (!(error instanceof AuthError) || !["unsupported_binding", "discovery_failed", "invalid_configuration"].includes(error.code)) throw error;
        // Obsolete capabilities or explicit principal changes rebuild outside locks.
      }
    }
    // Discovery and destination policy run before either binding or grant coordination.
    const target = await step(operation, resolveTarget(snapshotContext({ ...context, challenged: true }), options, operation));
    scopes(target.client.scopes);
    const allowed = scopes(target.client.allowedScopes ?? target.client.scopes);
    if ([...target.client.scopes, ...(target.client.requiredScopes ?? [])].some(scope => !allowed.includes(scope))) {
      throw new AuthError("access_denied");
    }
    const { clientSecret: _secret, ...nonSecret } = target.client;
    const value: StoredCredential = { token: "", scopes: [], generation: crypto.randomUUID(),
      bindingMetadata: { client: nonSecret, metadata: target.metadata } };
    await step(operation, store.coordinate(cacheKey, operation.signal, async () => {
      const latest = await step(operation, store.load(cacheKey, operation.signal));
      if (!await step(operation, store.compareAndSet(cacheKey, latest?.generation, { ...value, requiredScopes: latest?.requiredScopes ?? [] }, operation.signal))) {
        throw new AuthError("provider_failed");
      }
    }));
    return withBindingRequirements(target, cached?.requiredScopes ?? []);
  }
  function withBindingRequirements(target: ResolvedTarget, required: readonly string[]): ResolvedTarget {
    const allowed = target.client.allowedScopes ?? target.client.scopes;
    if (required.some(scope => !allowed.includes(scope))) throw new AuthError("access_denied");
    return { ...target, client: { ...target.client,
      requiredScopes: [...new Set([...(target.client.requiredScopes ?? []), ...required])] } };
  }
  async function recordBindingRequirements(context: DeliveryAuthContext, required: readonly string[], operation: Operation): Promise<void> {
    const key = bindingKey(options.namespace, context);
    await step(operation, store.coordinate(key, operation.signal, async () => {
      const current = await step(operation, store.load(key, operation.signal));
      if (!current?.bindingMetadata) throw new AuthError("provider_failed");
      if (!await step(operation, store.compareAndSet(key, current.generation, { ...current,
        requiredScopes: [...new Set([...(current.requiredScopes ?? []), ...required])] }, operation.signal))) {
        throw new AuthError("provider_failed");
      }
    }));
  }
  function checkedReady(value: StoredCredential, key: string, binding: string, target: ResolvedTarget): Ready {
    const allowed = target.client.allowedScopes ?? target.client.scopes;
    if (value.rejected) throw new AuthError("access_denied");
    if (value.scopes.some(scope => !allowed.includes(scope))) throw new AuthError("access_denied");
    if ([...(target.client.requiredScopes ?? []), ...(value.requiredScopes ?? [])].some(scope => !value.scopes.includes(scope))) {
      throw new AuthError(target.client.flow === "client_credentials" ? "access_denied" : "interaction_required");
    }
    return ready(value, key, binding);
  }
  async function prepare(input: DeliveryAuthContext, suppliedBudget: Operation, interactive = true): Promise<PrepareResult> {
    const budget = Object.freeze({ signal: suppliedBudget.signal, deadline: suppliedBudget.deadline });
    const context = snapshotContext(interactive && input.authentication === undefined ? { ...input, challenged: true } : input);
    return bounded(budget, async (operation) => {
      // No background cleanup: expiry is enforced at use and pruned on prepare.
      for (const record of pendingByKey.values()) {
        if (record.expiresAt <= Date.now() || record.signals.some(signal => signal.aborted)) retire(record);
      }
      const binding = identity(context);
      let target = await targetFor(context, operation);
      let key = grantKey(options.namespace, context, target.client);
      const observed = await load(key, operation);
      const observedRequirements = [...(target.client.requiredScopes ?? []), ...(observed?.requiredScopes ?? [])];
      if (observed && (!reusable(observed) || observedRequirements.some(scope => !observed.scopes.includes(scope)))) {
        // Refresh capabilities/endpoints can change. Rebuild outside the grant lock.
        target = await targetFor(context, operation, true);
        key = grantKey(options.namespace, context, target.client);
      }
      return step(operation, store.coordinate(key, operation.signal, async () => {
        operation.signal.throwIfAborted();
        const current = await load(key, operation);
        const required = [...new Set([...(target.client.requiredScopes ?? []), ...(current?.requiredScopes ?? [])])];
        if (reusable(current) && required.every(scope => current.scopes.includes(scope))) {
          return checkedReady(current, key, binding, target);
        }
        const requestedTarget = { ...target, client: { ...target.client,
          scopes: [...new Set([...target.client.scopes, ...required])] } };
        if (target.client.flow !== "client_credentials" && current?.refreshToken && !current.refreshRejected && !current.refreshQuarantined && required.every(scope => current.scopes.includes(scope))) {
          try {
            const token = await step(operation, refreshCredential({ ...target, client: { ...target.client, scopes: current.scopes.filter(scope => (target.client.allowedScopes ?? target.client.scopes).includes(scope)) } }, current.refreshToken, options, operation));
            return checkedReady(await save(key, current.generation, { ...token, requiredScopes: required, ...(token.rejected ? { refreshQuarantined: true } : {}),
              ...(token.refreshToken === undefined ? { refreshToken: current.refreshToken } : {}),
            }, operation), key, binding, target);
          } catch (error) {
            operation.signal.throwIfAborted();
            if (error instanceof AuthError && error.code === "refresh_rejected") {
              const saved = await step(operation, store.compareAndSet(key, current.generation,
                { ...current, rejected: true, refreshRejected: true }, operation.signal));
              if (!saved) throw new AuthError("provider_failed");
            }
            if (!(error instanceof AuthError && error.code === "refresh_rejected")) throw error;
            if (!interactive) throw new AuthError("interaction_required");
          }
        }
        if (target.client.flow === "client_credentials") {
          const token = await step(operation, acquireClientCredentials(requestedTarget, options, operation));
          return checkedReady(await save(key, current?.generation, { ...token, requiredScopes: required }, operation), key, binding, target);
        }
        if (!interactive) throw new AuthError("interaction_required");
        const existing = pendingByKey.get(key);
        if (existing?.pending && existing.baseGeneration === current?.generation && existing.expiresAt >= operation.deadline && existing.expiresAt > Date.now() &&
            existing.target.client.redirectUri === requestedTarget.client.redirectUri &&
            JSON.stringify(scopes(existing.target.client.scopes)) === JSON.stringify(scopes(requestedTarget.client.scopes)) &&
            JSON.stringify(scopes(existing.target.client.requiredScopes ?? [])) === JSON.stringify(scopes(target.client.requiredScopes ?? [])) &&
            existing.signals.every(signal => !signal.aborted) &&
            required.every(scope => existing.target.client.scopes.includes(scope))) return existing.pending;
        if (existing) forget(existing);
        const record: PendingRecord = { key, target: requestedTarget, identity: binding, baseGeneration: current?.generation,
          expiresAt: Math.min(operation.deadline, Date.now() + 600_000),
          signals: [...new Set([budget.signal, ...(context.signal ? [context.signal] : [])])] };
        // Reserve before asynchronous PKCE/destination policy work; remove only our entry.
        pendingByKey.set(key, record);
        try {
          record.login = await step(operation, startLogin(requestedTarget, options, operation));
          record.pending = Object.freeze({ type: "pending_login", authorizationUrl: record.login.authorizationUrl, expiresAt: record.expiresAt });
          pendingRecords.set(record.pending, record);
          retain(record);
          operation.signal.throwIfAborted();
          return record.pending;
        } catch (error) {
          forget(record);
          throw error;
        }
      }));
    }, context.signal ? [context.signal] : []);
  }
  async function complete(pending: PendingLogin, callback: string, budget: Operation): Promise<Ready> {
    const known = pendingRecords.get(pending);
    const terminal = ended.get(pending);
    terminal?.signal?.throwIfAborted();
    const enclosing = { ...budget, deadline: Math.min(budget.deadline, known?.expiresAt ?? terminal?.expiresAt ?? budget.deadline) };
    return bounded(enclosing, async (operation) => {
      const record = pendingRecords.get(pending);
      if (!record || !record.login) throw new AuthError("invalid_configuration");
      if (record.expiresAt <= Date.now()) throw new AuthError("interaction_required");
      return step(operation, store.coordinate(record.key, operation.signal, async () => {
        operation.signal.throwIfAborted();
        if (pendingByKey.get(record.key) !== record || pendingRecords.get(pending) !== record) throw new AuthError("invalid_configuration");
        try { validateCallback(record.target, record.login!, callback); }
        catch { throw new AuthError("access_denied"); }
        // A validated callback/code is single-use, including unsuccessful exchanges.
        pendingRecords.delete(pending);
        try {
          const current = await load(record.key, operation);
          if (current?.generation !== record.baseGeneration) throw new AuthError("invalid_configuration");
          const token = await step(operation, exchangeCode(record.target, record.login!, callback, options, operation));
          const stored = await save(record.key, record.baseGeneration, { ...token, requiredScopes: current?.requiredScopes ?? [] }, operation);
          return checkedReady(stored, record.key, record.identity, record.target);
        } finally {
          forget(record);
        }
      }));
    }, known?.signals);
  }
  async function challenge(input: AuthChallengeContext, budget: Operation): Promise<void> {
    const context = { ...snapshotContext(input), response: input.response, credential: input.credential };
    return bounded(budget, async (operation) => {
      const parameters = bearerParameters(context.response.headers.get("www-authenticate") ?? undefined);
      const insufficient = context.response.status === 403 && parameters.get("error") === "insufficient_scope";
      if (context.response.status === 403 && !insufficient) throw new AuthError("access_denied");
      const target = insufficient ? await targetFor(snapshotContext({ ...context, challenged: true }), operation) : undefined;
      const advertised = parameters.get("scope");
      const required = insufficient ? (advertised === undefined
        ? scopes(target!.hostRequiredScopes ?? []) : scopes(advertised.split(" "))) : [];
      if (insufficient && required.length === 0) throw new AuthError("access_denied");
      if (required.some(scope => !(target!.client.allowedScopes ?? target!.client.scopes).includes(scope))) {
        throw new AuthError("access_denied");
      }
      if (!context.credential) {
        if (insufficient) {
          await recordBindingRequirements(context, required, operation);
          if (target!.client.flow === "authorization_code_pkce") throw new AuthError("interaction_required");
          const { response: _response, credential: _credential, ...delivery } = context;
          await prepare({ ...delivery, challenged: true }, operation, false);
          return;
        }
        if (context.response.status === 401) {
          const { response, credential: _credential, ...delivery } = context;
          const challenge = response.headers.get("www-authenticate");
          await prepare({ ...delivery, challenged: true, ...(challenge === null ? {} : { challenge }) }, operation, false);
        }
        return;
      }
      const attempt = context.credential.attempt;
      const owner = typeof attempt === "object" && attempt !== null ? attempts.get(attempt) : undefined;
      if (!owner || owner.identity !== identity(context)) throw new AuthError("invalid_configuration");
      await step(operation, store.coordinate(owner.key, operation.signal, async () => {
        operation.signal.throwIfAborted();
        const current = await load(owner.key, operation);
        if (!current || current.generation !== owner.generation || (current.rejected && !insufficient)) return;
        if (!await step(operation, store.compareAndSet(owner.key, owner.generation,
          { ...current, rejected: true, requiredScopes: [...new Set([...(current.requiredScopes ?? []), ...required])] }, operation.signal))) throw new AuthError("provider_failed");
      }));
      if (insufficient && target?.client.flow !== "client_credentials") throw new AuthError("interaction_required");
    }, context.signal ? [context.signal] : []);
  }
  async function cancel(pending: PendingLogin, budget: Operation): Promise<void> {
    return bounded(budget, async (operation) => {
      const record = pendingRecords.get(pending);
      if (!record) return;
      await step(operation, store.coordinate(record.key, operation.signal, async () => {
        operation.signal.throwIfAborted();
        forget(record);
      }));
    });
  }
  function provider(host: { readonly budget: (context: DeliveryAuthContext) => Operation }): DeliveryAuthProvider {
    function deliveryBudget(context: DeliveryAuthContext): Operation {
      context.signal?.throwIfAborted();
      try { return host.budget(context); } catch (error) {
        context.signal?.throwIfAborted();
        throw classifyAuthError(error);
      }
    }
    return {
      async credential(input) {
        const context = snapshotContext(input);
        const budget = deliveryBudget(context);
        if (context.authentication === undefined && !context.challenged) {
          const known = await bounded(budget, operation => step(operation,
            store.load(bindingKey(options.namespace, context), operation.signal)), context.signal ? [context.signal] : []);
          if (!known?.bindingMetadata) return undefined;
        }
        const result = await prepare(context, budget, false);
        if (result.type === "pending_login") throw new AuthError("interaction_required");
        return result.credential;
      },
      async challenge(input) {
        const context = { ...snapshotContext(input), response: input.response, credential: input.credential };
        return challenge(context, deliveryBudget(context));
      },
    };
  }
  return Object.freeze({ prepare, complete, cancel, challenge, provider });
}
