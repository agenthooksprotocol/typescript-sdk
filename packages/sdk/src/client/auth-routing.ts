import { classifyAuthError } from "./auth.js";
import type { AuthChallengeContext, DeliveryAuthContext, DeliveryAuthProvider, DeliveryCredential, PreparedEndpoint } from "./auth.js";

export type AuthErrorCode =
  | "invalid_configuration" | "unsupported_binding" | "credential_unavailable"
  | "interaction_required" | "access_denied" | "refresh_rejected"
  | "discovery_failed" | "untrusted_destination" | "provider_failed";
export type AuthRecovery = "configure" | "login" | "retry" | "none";
const recovery: Record<AuthErrorCode, AuthRecovery> = {
  invalid_configuration: "configure", unsupported_binding: "configure",
  credential_unavailable: "configure", interaction_required: "login",
  access_denied: "none", refresh_rejected: "login", discovery_failed: "retry",
  untrusted_destination: "configure", provider_failed: "retry",
};
/** Safe to report: never retains provider errors, credentials, URLs or causes. */
export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly recovery: AuthRecovery;
  /**
   * Validated scope tokens the failed operation requires, on `interaction_required`
   * or `access_denied` only, deduplicated and sorted in ascending byte order. Pass
   * them back to a host `prepare` for step-up consent.
   */
  readonly requiredScopes?: readonly string[];
  /**
   * Set on every error thrown by `managedOAuth().complete()`: true when the pending
   * login named by the callback's `state` no longer exists after the call (consumed,
   * expired or unknown), false when it is still pending (for example after a stray
   * or invalid callback rejected before the login was claimed).
   */
  declare readonly loginEnded?: boolean;
  constructor(code: AuthErrorCode, requiredScopes?: readonly string[]) {
    const safe = typeof code === "string" && Object.hasOwn(recovery, code) ? code : "provider_failed";
    super(`Authentication failed: ${safe}`);
    this.name = "AuthError";
    this.code = safe;
    this.recovery = recovery[safe];
    if ((safe === "interaction_required" || safe === "access_denied") && Array.isArray(requiredScopes) &&
        requiredScopes.length > 0 && requiredScopes.every(scope => typeof scope === "string" && /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) {
      this.requiredScopes = Object.freeze([...new Set(requiredScopes)].sort());
    }
  }
}

type Destination = Readonly<{
  backendId: string;
  purpose: "event" | "upload";
  url: string;
}>;
export type AuthTarget = Destination & (
  | Readonly<{ type: "discover" }>
  | Readonly<{
      type: "bearer";
      source: Readonly<{ type: "environment"; name: string }>
        | Readonly<{ type: "reference"; reference: string }>;
    }>
  | Readonly<{
      type: "oauth";
      issuer: string;
      resource: string;
      clientId: string;
      flow: "authorization_code_pkce" | "client_credentials";
      scopes: readonly string[];
      clientSecretRef?: string;
    }>
);
function required(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) throw new AuthError("invalid_configuration");
  return value;
}
/** Normalize locally, without resolving secrets or performing discovery. */
export function normalizeAuthTarget(context: DeliveryAuthContext): AuthTarget {
  const common = { backendId: required(context.backendId), purpose: context.purpose, url: required(context.url) };
  if (common.purpose !== "event" && common.purpose !== "upload") throw new AuthError("invalid_configuration");
  try {
    const url = new URL(common.url);
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password || url.hash) throw new Error();
  } catch { throw new AuthError("invalid_configuration"); }
  const binding = context.authentication;
  if (!binding) return Object.freeze({ ...common, type: "discover" });
  if (binding.type === "bearer") {
    if ((binding.tokenEnv !== undefined) === (binding.tokenRef !== undefined)) throw new AuthError("invalid_configuration");
    const source = binding.tokenEnv !== undefined
      ? { type: "environment" as const, name: required(binding.tokenEnv) }
      : { type: "reference" as const, reference: required(binding.tokenRef) };
    return Object.freeze({ ...common, type: "bearer", source: Object.freeze(source) });
  }
  if (binding.type !== "oauth") throw new AuthError("unsupported_binding");
  if (binding.flow !== "authorization_code_pkce" && binding.flow !== "client_credentials") throw new AuthError("unsupported_binding");
  const scopes = binding.scopes ?? [];
  if (!Array.isArray(scopes) || scopes.some((scope) => typeof scope !== "string" || !scope.trim())) throw new AuthError("invalid_configuration");
  return Object.freeze({
    ...common, type: "oauth",
    issuer: required(binding.issuer),
    resource: required(binding.resource),
    clientId: required(binding.clientId),
    flow: binding.flow === "client_credentials" ? "client_credentials" : "authorization_code_pkce",
    scopes: Object.freeze([...scopes]),
    ...(binding.clientSecretRef === undefined
      ? {} : { clientSecretRef: required(binding.clientSecretRef) }),
  });
}

/** OAuth scopes are a set; object insertion order is not binding identity. */
function sameTarget(left: AuthTarget, right: AuthTarget): boolean {
  if (left.backendId !== right.backendId || left.purpose !== right.purpose || left.url !== right.url || left.type !== right.type) return false;
  if (left.type === "bearer" && right.type === "bearer") {
    return left.source.type === right.source.type && (left.source.type === "environment"
      ? right.source.type === "environment" && left.source.name === right.source.name
      : right.source.type === "reference" && left.source.reference === right.source.reference);
  }
  if (left.type === "oauth" && right.type === "oauth") {
    return left.issuer === right.issuer && left.resource === right.resource && left.clientId === right.clientId
      && left.flow === right.flow && left.clientSecretRef === right.clientSecretRef
      && new Set(left.scopes).size === new Set(right.scopes).size
      && left.scopes.every((scope) => right.scopes.includes(scope));
  }
  return left.type === "discover";
}

function authenticationSnapshot(binding: DeliveryAuthContext["authentication"]): DeliveryAuthContext["authentication"] {
  if (!binding) return undefined;
  if (binding.type !== "oauth" || binding.scopes === undefined) return Object.freeze({ ...binding });
  const scopes = [...binding.scopes];
  Object.freeze(scopes);
  return Object.freeze({ ...binding, scopes });
}

export interface AuthCompositionOptions {
  readonly bearer?: DeliveryAuthProvider;
  readonly oauth?: DeliveryAuthProvider;
  /** Invoked only after a challenge when no binding is configured. */
  readonly discover?: DeliveryAuthProvider;
}

async function invoke<T>(context: DeliveryAuthContext, operation: () => T | Promise<T>): Promise<T> {
  context.signal?.throwIfAborted();
  const signal = context.signal;
  let abort: (() => void) | undefined;
  try {
    const result = Promise.resolve().then(() => {
      signal?.throwIfAborted();
      return operation();
    });
    if (!signal) return await result;
    const cancelled = new Promise<never>((_, reject) => {
      abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    });
    const value = await Promise.race([result, cancelled]);
    signal.throwIfAborted();
    return value;
  } catch (error) {
    signal?.throwIfAborted();
    throw classifyAuthError(error);
  } finally {
    if (abort) signal?.removeEventListener("abort", abort);
  }
}

/** Additive routing only: providers retain OAuth, storage, UI and replay ownership. */
export function composeAuth(options: AuthCompositionOptions, defaultBearer: DeliveryAuthProvider): DeliveryAuthProvider {
  const routes = { bearer: options.bearer ?? defaultBearer, oauth: options.oauth, discover: options.discover };
  const attempts = new WeakMap<object, {
    provider: DeliveryAuthProvider;
    credential: DeliveryCredential;
    target: AuthTarget;
    authentication: DeliveryAuthContext["authentication"];
  }>();
  function route(context: DeliveryAuthContext) {
    const target = normalizeAuthTarget(context);
    const provider = routes[target.type];
    if (!provider && target.type !== "discover") throw new AuthError("unsupported_binding");
    return { target, provider };
  }
  const notifiers = [...new Set([routes.bearer, routes.oauth, routes.discover])]
    .filter((provider): provider is DeliveryAuthProvider => typeof provider?.onPrepared === "function");
  return {
    ...(notifiers.length ? {
      onPrepared(listener: (endpoint: PreparedEndpoint) => void) {
        const unsubscribe = notifiers.map(provider => provider.onPrepared!(listener));
        return () => { for (const stop of unsubscribe) stop(); };
      },
    } : {}),
    ...(routes.bearer.resolveEnvironmentVariable ? { resolveEnvironmentVariable: routes.bearer.resolveEnvironmentVariable.bind(routes.bearer) } : {}),
    ...(routes.bearer.resolveCredentialReference ? { resolveCredentialReference: routes.bearer.resolveCredentialReference.bind(routes.bearer) } : {}),
    async credential(context) {
      context.signal?.throwIfAborted();
      const { target, provider } = route(context);
      if (!provider) {
        if (context.challenged || context.challenge !== undefined) throw new AuthError("unsupported_binding");
        return undefined;
      }
      const authentication = authenticationSnapshot(context.authentication);
      const { authentication: _authentication, rejectedCredential, ...rest } = context;
      // A replay names the credential its challenge rejected: hand the provider its own credential.
      const rejected = rejectedCredential && typeof rejectedCredential.attempt === "object" && rejectedCredential.attempt !== null
        ? attempts.get(rejectedCredential.attempt) : undefined;
      const originalContext = { ...rest, backendId: target.backendId, purpose: target.purpose, url: target.url,
        ...(authentication ? { authentication } : {}), ...(rejected?.provider === provider ? { rejectedCredential: rejected.credential } : {}) };
      return invoke(context, async () => {
        const credential = await provider.credential(originalContext);
        if (credential === undefined && target.type === "discover" && !context.challenged && context.challenge === undefined) return undefined;
        if (!credential || credential.type !== "bearer" || typeof credential.token !== "string" || !credential.token || /[\r\n]/.test(credential.token)) throw new AuthError("credential_unavailable");
        const attempt = Object.freeze({});
        attempts.set(attempt, { provider, credential, target, authentication });
        return { type: "bearer", token: credential.token, attempt };
      });
    },
    async challenge(context: AuthChallengeContext) {
      context.signal?.throwIfAborted();
      const attempt = context.credential?.attempt;
      const owner = typeof attempt === "object" && attempt !== null ? attempts.get(attempt) : undefined;
      if (context.credential) {
        if (!owner || !sameTarget(owner.target, normalizeAuthTarget(context))) throw new AuthError("invalid_configuration");
        const { authentication: _authentication, ...rest } = context;
        await invoke(context, () => owner.provider.challenge({ ...rest,
          ...(owner.authentication ? { authentication: owner.authentication } : {}), credential: owner.credential }));
      } else {
        const { provider } = route(context);
        if (provider) await invoke(context, () => provider.challenge(context));
      }
    },
  };
}
