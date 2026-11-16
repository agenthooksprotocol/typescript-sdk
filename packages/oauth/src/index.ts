import { AuthError, normalizeAuthTarget } from "agenthooksprotocol/client/auth";
import type { AuthChallengeContext, DeliveryAuthContext, DeliveryAuthProvider, DeliveryCredential } from "agenthooksprotocol/client/auth";
import { resolveTarget } from "./discovery.js";
import { acquireClientCredentials, exchangeCode, refreshCredential, startLogin } from "./protocol.js";
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
  return JSON.stringify([target.backendId, target.purpose, target.url, target.type,
    target.type === "oauth" ? [target.issuer, target.resource, target.clientId, target.flow,
      [...target.scopes].sort(), target.clientSecretRef ?? null] :
      target.type === "bearer" ? target.source : null]);
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
function keyFor(namespace: string, context: DeliveryAuthContext, target: ResolvedTarget): string {
  const client = target.client;
  return JSON.stringify([namespace, identity(context), context.backendId, context.purpose, context.url,
    client.issuer, client.resource, client.clientId, client.flow, [...client.scopes].sort()]);
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
    throw new AuthError(error instanceof AuthError ? error.code : "provider_failed");
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
    if (!value.token || /[\r\n]/.test(value.token) || !Number.isFinite(value.expiresAt) ||
        value.expiresAt <= Date.now() || !value.generation) throw new AuthError("credential_unavailable");
    const attempt = Object.freeze({});
    attempts.set(attempt, { key, generation: value.generation, identity: binding });
    return Object.freeze({ type: "ready", credential: Object.freeze({ type: "bearer", token: value.token, attempt }) });
  }
  function reusable(value: StoredCredential | undefined): value is StoredCredential {
    return value !== undefined && !value.rejected && value.expiresAt > Date.now() + 30_000;
  }
  async function load(key: string, operation: Operation): Promise<StoredCredential | undefined> {
    const value = await step(operation, store.load(key, operation.signal));
    if (value === undefined) return undefined;
    if (!Array.isArray(value.scopes) || typeof value.generation !== "string" || !value.generation ||
        typeof value.token !== "string" || !Number.isFinite(value.expiresAt)) {
      throw new AuthError("credential_unavailable");
    }
    return Object.freeze({ ...value, scopes: Object.freeze([...value.scopes]) });
  }
  async function save(key: string, expected: string | undefined, token: TokenValue, operation: Operation) {
    operation.signal.throwIfAborted();
    const value: StoredCredential = Object.freeze({ ...token, scopes: Object.freeze([...token.scopes]), generation: crypto.randomUUID() });
    const saved = await step(operation, store.compareAndSet(key, expected, value, operation.signal));
    if (!saved) throw new AuthError("provider_failed");
    return value;
  }
  async function prepare(input: DeliveryAuthContext, suppliedBudget: Operation): Promise<PrepareResult> {
    const budget = Object.freeze({ signal: suppliedBudget.signal, deadline: suppliedBudget.deadline });
    const context = snapshotContext(input);
    return bounded(budget, async (operation) => {
      // No background cleanup: expiry is enforced at use and pruned on prepare.
      for (const record of pendingByKey.values()) {
        if (record.expiresAt <= Date.now() || record.signals.some(signal => signal.aborted)) retire(record);
      }
      const binding = identity(context);
      const target = await step(operation, resolveTarget(context, options, operation));
      const key = keyFor(options.namespace, context, target);
      return step(operation, store.coordinate(key, operation.signal, async () => {
        operation.signal.throwIfAborted();
        const current = await load(key, operation);
        if (current && (!Array.isArray(current.scopes) ||
            current.scopes.some((scope) => !target.client.scopes.includes(scope)))) {
          throw new AuthError("credential_unavailable");
        }
        if (reusable(current) && target.client.scopes.every((scope) => current.scopes.includes(scope))) return ready(current, key, binding);
        if (current?.refreshToken && !current.refreshRejected) {
          try {
            const token = await step(operation, refreshCredential(target, current.refreshToken, options, operation));
            return ready(await save(key, current.generation, { ...token,
              ...(token.refreshToken === undefined ? { refreshToken: current.refreshToken } : {}),
            }, operation), key, binding);
          } catch (error) {
            operation.signal.throwIfAborted();
            if (error instanceof AuthError && error.code === "refresh_rejected") {
              const saved = await step(operation, store.compareAndSet(key, current.generation,
                { ...current, rejected: true, refreshRejected: true }, operation.signal));
              if (!saved) throw new AuthError("provider_failed");
            }
            throw error;
          }
        }
        if (target.client.flow === "client_credentials") {
          const token = await step(operation, acquireClientCredentials(target, options, operation));
          return ready(await save(key, current?.generation, token, operation), key, binding);
        }
        const existing = pendingByKey.get(key);
        if (existing?.pending && existing.baseGeneration === current?.generation && existing.expiresAt > Date.now() &&
            existing.signals.every(signal => !signal.aborted)) return existing.pending;
        if (existing) forget(existing);
        const record: PendingRecord = { key, target, identity: binding, baseGeneration: current?.generation,
          expiresAt: Math.min(operation.deadline, Date.now() + 600_000),
          signals: [...new Set([budget.signal, ...(context.signal ? [context.signal] : [])])] };
        // Reserve before asynchronous PKCE/destination policy work; remove only our entry.
        pendingByKey.set(key, record);
        try {
          record.login = await step(operation, startLogin(target, options, operation));
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
        // A callback/code is single-use, including unsuccessful exchanges.
        pendingRecords.delete(pending);
        try {
          const current = await load(record.key, operation);
          if (current?.generation !== record.baseGeneration) throw new AuthError("invalid_configuration");
          const token = await step(operation, exchangeCode(record.target, record.login!, callback, options, operation));
          const stored = await save(record.key, record.baseGeneration, token, operation);
          return ready(stored, record.key, record.identity);
        } finally {
          forget(record);
        }
      }));
    }, known?.signals);
  }
  async function challenge(input: AuthChallengeContext, budget: Operation): Promise<void> {
    const context = { ...snapshotContext(input), response: input.response, credential: input.credential };
    return bounded(budget, async (operation) => {
      if (!context.credential) return;
      const attempt = context.credential.attempt;
      const owner = typeof attempt === "object" && attempt !== null ? attempts.get(attempt) : undefined;
      if (!owner || owner.identity !== identity(context)) throw new AuthError("invalid_configuration");
      await step(operation, store.coordinate(owner.key, operation.signal, async () => {
        operation.signal.throwIfAborted();
        const current = await load(owner.key, operation);
        if (!current || current.generation !== owner.generation || current.rejected) return;
        if (!await step(operation, store.compareAndSet(owner.key, owner.generation,
          { ...current, rejected: true }, operation.signal))) throw new AuthError("provider_failed");
      }));
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
        throw new AuthError(error instanceof AuthError ? error.code : "provider_failed");
      }
    }
    return {
      async credential(input) {
        const context = snapshotContext(input);
        const result = await prepare(context, deliveryBudget(context));
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
