import type { AuthChallengeContext, DeliveryAuthContext, DeliveryAuthProvider, DeliveryCredential } from "./auth.js";

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
  constructor(code: AuthErrorCode) {
    const safe = typeof code === "string" && Object.hasOwn(recovery, code) ? code : "provider_failed";
    super(`Authentication failed: ${safe}`);
    this.name = "AuthError";
    this.code = safe;
    this.recovery = recovery[safe];
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
    throw new AuthError(error instanceof AuthError ? error.code : "provider_failed");
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
    backendId: string;
    purpose: string;
    url: string;
  }>();
  function route(context: DeliveryAuthContext) {
    const target = normalizeAuthTarget(context);
    const provider = routes[target.type];
    if (!provider && target.type !== "discover") throw new AuthError("unsupported_binding");
    return { target, provider };
  }
  return {
    ...(routes.bearer.resolveEnvironmentVariable ? { resolveEnvironmentVariable: routes.bearer.resolveEnvironmentVariable.bind(routes.bearer) } : {}),
    ...(routes.bearer.resolveCredentialReference ? { resolveCredentialReference: routes.bearer.resolveCredentialReference.bind(routes.bearer) } : {}),
    async credential(context) {
      context.signal?.throwIfAborted();
      const { target, provider } = route(context);
      if (target.type === "discover" && !context.challenged && context.challenge === undefined) return undefined;
      if (!provider) {
        if (context.challenged || context.challenge !== undefined) throw new AuthError("unsupported_binding");
        return undefined;
      }
      return invoke(context, async () => {
        const credential = await provider.credential(context);
        if (!credential || credential.type !== "bearer" || typeof credential.token !== "string" || !credential.token || /[\r\n]/.test(credential.token)) throw new AuthError("credential_unavailable");
        const attempt = Object.freeze({});
        attempts.set(attempt, { provider, credential, backendId: context.backendId, purpose: context.purpose, url: context.url });
        return { type: "bearer", token: credential.token, attempt };
      });
    },
    async challenge(context: AuthChallengeContext) {
      context.signal?.throwIfAborted();
      const attempt = context.credential?.attempt;
      const owner = typeof attempt === "object" && attempt !== null ? attempts.get(attempt) : undefined;
      if (context.credential) {
        if (!owner || owner.backendId !== context.backendId || owner.purpose !== context.purpose || owner.url !== context.url) throw new AuthError("invalid_configuration");
        await invoke(context, () => owner.provider.challenge({ ...context, credential: owner.credential }));
      } else {
        const { provider } = route(context);
        if (provider) await invoke(context, () => provider.challenge(context));
      }
    },
  };
}
