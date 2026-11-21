import type { Authentication } from "../draft/raw.js";
import { AuthError, composeAuth, type AuthCompositionOptions, type AuthErrorCode } from "./auth-routing.js";
import { bearerParameters } from "./challenge.js";
import { classify, coverage, decide, parseChallenge, type DecisionConfig, type DecisionOperation } from "./decision.js";
import { responseScopes } from "./scope.js";
export { AuthError, normalizeAuthTarget } from "./auth-routing.js";
export type { AuthErrorCode, AuthRecovery, AuthTarget, AuthCompositionOptions } from "./auth-routing.js";

/**
 * Classify across SDK copies without retaining untrusted messages or causes.
 * Only the caller's own aborted `signal` rethrows (its native reason); an
 * AbortError/TimeoutError raised by a provider is an operational failure.
 */
export function classifyAuthError(error: unknown, fallback: AuthErrorCode = "provider_failed", signal?: AbortSignal): AuthError {
  signal?.throwIfAborted();
  if (error instanceof AuthError) return error;
  let code: unknown, requiredScopes: unknown;
  try {
    if (typeof error === "object" && error !== null) ({ code, requiredScopes } = error as { code?: unknown; requiredScopes?: unknown });
  } catch { /* Untrusted provider objects may have throwing accessors. */ }
  const allowed: readonly string[] = [
    "invalid_configuration", "unsupported_binding", "credential_unavailable",
    "interaction_required", "access_denied", "refresh_rejected",
    "discovery_failed", "untrusted_destination", "provider_failed",
  ];
  // The constructor re-validates scopes from another SDK copy's AuthError.
  return typeof code === "string" && allowed.includes(code)
    ? new AuthError(code as AuthErrorCode, Array.isArray(requiredScopes) ? requiredScopes : undefined)
    : new AuthError(fallback);
}

export interface Credential {
  token: string;
  /** Absolute expiry in milliseconds since the Unix epoch. */
  expiresAt?: number;
  refreshToken?: string;
  scopes?: string[];
}

/** Context for a selected delivery binding, or an optional standalone auth helper. */
export interface AuthContext {
  /** Selected registration backend. Omitted for standalone authentication calls. */
  backendId?: string;
  /** Independent delivery binding. Omitted for standalone authentication calls. */
  purpose?: "event" | "upload";
  authentication?: Authentication;
  url: string;
  signal?: AbortSignal;
  challenge?: string;
  /**
   * Status of the challenged response (401 or 403), set by Hooks on the replay. When
   * absent with a `challenge`, `error="insufficient_scope"` means 403, otherwise 401.
   */
  challengeStatus?: number;
  /** Set on a 401 even when WWW-Authenticate is absent. */
  challenged?: boolean;
  /**
   * The credential the challenged response rejected, set by Hooks on the replay, so the
   * provider can tell a newer stored grant from the one the server refused. Never log it.
   */
  rejectedCredential?: DeliveryCredential;
  cache?: Map<string, Credential>;
  /** Optional endpoint discovery state; factory also scopes this by cache identity. */
  discoveryCache?: Map<
    string,
    { client: OAuthClient; metadata: OAuthMetadata }
  >;
  /** Installed by the factory so exported defaults retain composed overrides. */
  provider?: AuthProvider;
  authOptions?: AuthOptions;
}
/** The delivery mechanisms currently supported by AHP all use bearer tokens. */
export interface DeliveryCredential {
  type: "bearer";
  token: string;
  /** Provider-owned identity, returned unchanged on rejection; never log it. */
  attempt?: unknown;
}

/** Hooks always supplies backend identity and the independently selected binding. */
export interface DeliveryAuthContext extends AuthContext {
  backendId: string;
  purpose: "event" | "upload";
}

export interface AuthChallengeContext extends DeliveryAuthContext {
  /** Actual endpoint response, including status and WWW-Authenticate headers. */
  response: Response;
  /** Exact credential used for this attempt, including its opaque attempt identity. */
  credential: DeliveryCredential | undefined;
}

/**
 * Caller-owned authentication infrastructure. Hooks neither closes this provider
 * nor manages its token lifecycle. Both callbacks must honor the operation signal.
 * Credentials and attempt identities must not be included in diagnostics.
 */
export interface DeliveryAuthProvider {
  /** Optional shared secret resolvers for configured delivery headers. */
  resolveEnvironmentVariable?: AuthProvider["resolveEnvironmentVariable"];
  resolveCredentialReference?: AuthProvider["resolveCredentialReference"];
  /** Undefined means no credential; configured authentication must fail closed. */
  credential(
    context: DeliveryAuthContext,
  ): DeliveryCredential | undefined | Promise<DeliveryCredential | undefined>;
  /**
   * Record a rejection before credentials are requested again. This does not
   * authorize replay: Hooks decides whether a bounded retry is protocol-safe.
   */
  challenge(context: AuthChallengeContext): void | Promise<void>;
  /**
   * Optional: subscribe to successful host prepares (including a completed login)
   * that made credentials available for an endpoint. Hooks uses it to re-attempt
   * configuration discovery for a backend skipped as unavailable. Returns an
   * unsubscribe function.
   */
  onPrepared?(listener: (endpoint: PreparedEndpoint) => void): () => void;
}

/** The endpoint a successful host prepare made credentials available for. */
export type PreparedEndpoint = Readonly<{ backendId: string; purpose: "event" | "upload"; url: string }>;

export interface OAuthClient {
  issuer: string;
  resource: string;
  clientId: string;
  flow: "authorization_code_pkce" | "client_credentials";
  scopes?: string[];
  /** Local ceiling; defaults to requested scopes. */
  allowedScopes?: string[];
  /** Explicit operation requirements, not all requested scopes. */
  requiredScopes?: string[];
  clientSecretRef?: string;
  redirectUri?: string;
}
export interface AuthorizationRequest {
  url: string;
  redirectUri: string;
  state: string;
  signal?: AbortSignal;
}
export interface OAuthMetadata {
  issuer: string;
  token_endpoint: string;
  authorization_endpoint?: string;
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
}
export interface TokenRequest {
  client: OAuthClient;
  metadata: OAuthMetadata;
  parameters: URLSearchParams;
}
export interface AuthorizationCodeRequest extends TokenRequest {
  code: string;
  verifier: string;
  redirectUri: string;
}
export interface AuthOptions extends Partial<AuthProvider> {
  fetch?: typeof globalThis.fetch;
  /** Trusted DNS adapter; production adapters must enforce the checked addresses. */
  resolveHostname?: (hostname: string) => Promise<readonly string[]>;
  /** Exact origins permitted for explicitly trusted local test/process boundaries. */
  allowedLoopbackOrigins?: readonly string[];
  /** Optional additional host restrictions, applied after built-in DNS/private-network checks. */
  validateDestination?: (
    url: URL,
    purpose: "metadata" | "authorization" | "token",
    context: AuthContext,
  ) => void | Promise<void>;
  /** Automatic discovery never selects a client identity or trusts an issuer itself. */
  selectClient?: (
    issuers: readonly string[],
    resource: string,
    context: AuthContext,
  ) => OAuthClient | Promise<OAuthClient>;
  /** Receives the PKCE URL and returns the complete callback URL, not just a code. */
  authorize?: (
    request: AuthorizationRequest,
    context: AuthContext,
  ) => string | URL | Promise<string | URL>;
  redirectUri?: string;
  now?: () => number;
  expirySkewMs?: number;
}
export interface AuthProvider extends DeliveryAuthProvider {
  authenticate(
    context: AuthContext,
    options?: AuthOptions,
  ): Promise<Credential | undefined>;
  resolveEnvironmentVariable(
    name: string,
    context?: AuthContext,
  ): string | undefined | Promise<string | undefined>;
  resolveCredentialReference(
    reference: string,
    context: AuthContext,
  ): string | undefined | Promise<string | undefined>;
  discover(
    context: AuthContext,
    options?: AuthOptions,
  ): Promise<{ client: OAuthClient; metadata: OAuthMetadata }>;
  exchangeAuthorizationCode(
    request: AuthorizationCodeRequest,
    context: AuthContext,
    options?: AuthOptions,
  ): Promise<Credential>;
  getToken(
    key: string,
    context: AuthContext,
  ): Credential | undefined | Promise<Credential | undefined>;
  setToken(
    key: string,
    credential: Credential,
    context: AuthContext,
  ): void | Promise<void>;
  deleteToken(key: string, context: AuthContext): void | Promise<void>;
  refresh(
    context: AuthContext,
    request: TokenRequest,
    refreshToken: string,
    options?: AuthOptions,
  ): Promise<Credential>;
  clientCredentials(
    context: AuthContext,
    request: TokenRequest,
    options?: AuthOptions,
  ): Promise<Credential>;
  requestToken(
    context: AuthContext,
    request: TokenRequest,
    options?: AuthOptions,
  ): Promise<Credential>;
}

const TRANSFER_TIMEOUT_MS = 30_000;
/** Rotated refresh tokens carried by invalid token responses, keyed by the thrown error. */
const rotatedRefresh = new WeakMap<object, string>();
/** Credentials whose token response omitted `scope`: a refresh inherits the previous grant. */
const inheritedScopes = new WeakSet<object>();
function error(message: string): never {
  // Never include credential values, callback URLs, or token endpoint bodies.
  throw new Error(`Authentication failed: ${message}`);
}
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    error("invalid metadata");
  return value as Record<string, unknown>;
}
function string(value: unknown, name: string): string {
  if (typeof value !== "string" || !value) error(`missing ${name}`);
  return value;
}
function strings(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string"))
    error("invalid metadata list");
  return value as string[];
}
function loopback(host: string): boolean {
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "[::1]" ||
    host === "::1" ||
    /^127\./.test(host)
  );
}
/** Expand an IPv6 literal (optionally with a dotted IPv4 tail) to eight hextets. */
function ipv6Hextets(host: string): number[] | undefined {
  let text = host;
  const tail = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (tail) {
    const v4 = ipv4Octets(tail[2]!);
    if (!v4) return undefined;
    text = `${tail[1]}${((v4[0]! << 8) | v4[1]!).toString(16)}:${((v4[2]! << 8) | v4[3]!).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const part = (value: string) => (value === "" ? [] : value.split(":"));
  const head = part(halves[0]!), rest = halves.length === 2 ? part(halves[1]!) : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return undefined;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...rest];
  if (groups.some((group) => !/^[\da-f]{1,4}$/.test(group))) return undefined;
  return groups.map((group) => parseInt(group, 16));
}
function ipv4Octets(host: string): number[] | undefined {
  const parts = host.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return undefined;
  const octets = parts.map(Number);
  return octets.every((n) => n <= 255) ? octets : undefined;
}
function publicIPv4([a = 0, b = 0, c = 0]: readonly number[]): boolean {
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  );
}
/**
 * Only globally routable unicast destinations are public. IPv6 forms that embed an
 * IPv4 address (IPv4-mapped, IPv4-compatible, NAT64 64:ff9b::/96 and 6to4
 * 2002::/16) are checked as that IPv4 address.
 */
function publicAddress(address: string): boolean {
  const host = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host.includes(":")) {
    const octets = ipv4Octets(host);
    return octets !== undefined && publicIPv4(octets);
  }
  const h = ipv6Hextets(host.replace(/%.*$/, ""));
  if (!h) return false;
  const v4 = (high: number, low: number) => [high >> 8, high & 0xff, low >> 8, low & 0xff];
  const zero = (from: number, to: number) => h.slice(from, to).every((n) => n === 0);
  // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible; also covers :: and ::1).
  if (zero(0, 5) && (h[5] === 0xffff || h[5] === 0)) return publicIPv4(v4(h[6]!, h[7]!));
  // 64:ff9b::a.b.c.d (NAT64 well-known prefix).
  if (h[0] === 0x64 && h[1] === 0xff9b && zero(2, 6)) return publicIPv4(v4(h[6]!, h[7]!));
  // 2002:AABB:CCDD::/48 (6to4).
  if (h[0] === 0x2002) return publicIPv4(v4(h[1]!, h[2]!));
  // Global unicast 2000::/3, except documentation 2001:db8::/32 and Teredo 2001::/32.
  return (h[0]! & 0xe000) === 0x2000 && !(h[0] === 0x2001 && (h[1] === 0xdb8 || h[1] === 0));
}
function secureUrl(value: string, options: AuthOptions = {}): URL {
  const url = new URL(value);
  const local =
    url.protocol === "http:" &&
    loopback(url.hostname) &&
    options.allowedLoopbackOrigins?.includes(url.origin);
  if (
    (url.protocol !== "https:" && !local) ||
    url.username ||
    url.password ||
    url.hash
  )
    error("HTTPS URL required");
  return url;
}
type CheckedURL = URL & { resolvedAddresses: readonly string[] };
async function destination(
  value: string,
  purpose: "metadata" | "authorization" | "token",
  context: AuthContext,
  options: AuthOptions,
): Promise<CheckedURL> {
  const url = secureUrl(value, options);
  const host = url.hostname.toLowerCase();
  const local =
    loopback(host) && options.allowedLoopbackOrigins?.includes(url.origin);
  if (!local) {
    if (
      loopback(host) ||
      host.endsWith(".local") ||
      (!host.includes(".") && !host.includes(":"))
    )
      error("forbidden destination");
    if ((/^[\d.]+$/.test(host) || host.includes(":")) && !publicAddress(host))
      error("forbidden destination");
  }
  let addresses: readonly string[] = host.includes(":")
    ? ["::1"]
    : ["127.0.0.1"];
  if (!local) {
    addresses = await withinBudget(
      (async () => {
        if (options.resolveHostname) return options.resolveHostname(host);
        // Keep the Node-only resolver lazy: browser hosts must provide a resolver
        // and a fetch adapter that enforces the checked destination addresses.
        const moduleName = "node:dns/promises";
        const dns = (await import(moduleName)) as {
          lookup(
            host: string,
            options: { all: true },
          ): Promise<{ address: string }[]>;
        };
        return (
          await dns.lookup(host.replace(/^\[|\]$/g, ""), { all: true })
        ).map((entry) => entry.address);
      })(),
      context.signal,
    );
    if (
      !addresses.length ||
      addresses.some((address) => !publicAddress(address))
    )
      error("forbidden resolved destination");
  }
  if (options.validateDestination)
    await withinBudget(
      Promise.resolve(options.validateDestination(url, purpose, context)),
      context.signal,
    );
  return Object.assign(url, { resolvedAddresses: addresses });
}

/** Node's default transport pins the checked addresses, preventing DNS rebinding.
 * A custom fetch is a trusted host adapter and receives resolvedAddresses on URL.
 * Redirects are never followed, and token/metadata response bodies are bounded.
 */
async function fetchChecked(
  url: CheckedURL,
  init: RequestInit,
  options: AuthOptions,
): Promise<Response> {
  if (options.fetch) return options.fetch(url, init);
  interface Incoming extends AsyncIterable<Uint8Array> {
    statusCode?: number;
    headers: Record<string, string | string[] | undefined>;
  }
  interface Outgoing {
    on(event: "error", listener: (error: Error) => void): void;
    end(body?: string): void;
    destroy(error?: Error): void;
  }
  const moduleName = url.protocol === "http:" ? "node:http" : "node:https";
  const http = (await import(moduleName)) as {
    request(
      url: URL,
      options: Record<string, unknown>,
      callback: (response: Incoming) => void,
    ): Outgoing;
  };
  return new Promise<Response>((resolve, reject) => {
    const request = http.request(
      url,
      {
        method: init.method ?? "GET",
        headers: Object.fromEntries(new Headers(init.headers)),
        signal: init.signal,
        lookup(
          _hostname: string,
          lookupOptions: { all?: boolean },
          callback: (...args: unknown[]) => void,
        ) {
          const addresses = url.resolvedAddresses.map((address) => ({
            address,
            family: address.includes(":") ? 6 : 4,
          }));
          if (lookupOptions.all) callback(null, addresses);
          else callback(null, addresses[0]?.address, addresses[0]?.family);
        },
      },
      (incoming) => {
        void (async () => {
          const headers = new Headers();
          for (const [key, value] of Object.entries(incoming.headers)) {
            if (Array.isArray(value))
              for (const item of value) headers.append(key, item);
            else if (value !== undefined) headers.set(key, value);
          }
          const chunks: Uint8Array[] = [];
          let size = 0;
          for await (const chunk of incoming) {
            size += chunk.length;
            if (size > 1_048_576) {
              request.destroy();
              error("metadata or token response too large");
            }
            chunks.push(chunk);
          }
          const body = new Uint8Array(size);
          let offset = 0;
          for (const chunk of chunks) {
            body.set(chunk, offset);
            offset += chunk.length;
          }
          const status = incoming.statusCode ?? 500;
          resolve(
            new Response([204, 205, 304].includes(status) ? null : body, {
              status,
              headers,
            }),
          );
        })().catch(reject);
      },
    );
    request.on("error", () =>
      reject(new Error("Authentication failed: network request failed")),
    );
    request.end(init.body?.toString());
  });
}
async function withinBudget<T>(
  promise: Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) {
    // The host callback may have aborted synchronously after returning work.
    void promise.catch(() => {});
    signal.throwIfAborted();
  }
  return new Promise<T>((resolve, reject) => {
    const abort = () =>
      reject(signal.reason ?? new Error("Authentication cancelled"));
    signal.addEventListener("abort", abort, { once: true });
    promise
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
  });
}
function validateCredential(
  credential: Credential,
  options: AuthOptions,
): Credential {
  if (!credential.token || /[\s\x00-\x1f\x7f]/.test(credential.token))
    error("invalid bearer token");
  if (
    credential.expiresAt !== undefined &&
    (!Number.isFinite(credential.expiresAt) ||
      credential.expiresAt <= (options.now ?? Date.now)())
  )
    error("expired token");
  return credential;
}
function cacheKey(context: AuthContext, client: OAuthClient): string {
  return JSON.stringify([
    context.url,
    client.issuer,
    client.resource,
    client.clientId,
    client.flow,
    client.clientSecretRef,
    [...(client.scopes ?? [])].sort(),
  ]);
}
/** S, C, H and the preset's scopes of a legacy client, as `decide` reads them. */
function legacyConfig(client: OAuthClient, context: AuthContext): DecisionConfig {
  const binding = context.authentication as { type?: unknown; scopes?: unknown } | undefined;
  const preset = binding?.type === "oauth" && Array.isArray(binding.scopes) ? binding.scopes as string[] : undefined;
  return { flow: client.flow, requested: client.scopes ?? [], ceiling: client.allowedScopes ?? client.scopes ?? [],
    hostRequired: client.requiredScopes ?? [], ...(preset ? { presetScopes: preset } : {}) };
}
function legacyChallenge(context: AuthContext) {
  return parseChallenge(context.challengeStatus, context.challenge, context.challenged === true);
}
/** Steps 1-4 of `decide` for a selected client, before any authorization-server I/O. */
function legacyGate(client: OAuthClient, context: AuthContext): void {
  const { outcome } = decide({ op: "credential", config: legacyConfig(client, context), challenge: legacyChallenge(context) });
  if (outcome.type === "fail" && outcome.step <= 4) throw outcome.error;
}
/** Section 4 at the legacy boundary: SDK auth errors keep scopes only from `decide`. */
function legacyClassify(error: unknown): unknown {
  let name: unknown;
  try { name = (error as { name?: unknown } | null)?.name; } catch { return error; }
  return error instanceof AuthError || name === "AuthError" ? classify(classifyAuthError(error)) : error;
}

function base64url(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function challengeParameter(challenge: string | undefined, name: string): string | undefined {
  // An unparseable challenge has no usable hint; `decide` refuses it (step 2).
  try { return bearerParameters(challenge).get(name); } catch { return undefined; }
}
async function metadataAt(
  urls: string[],
  context: AuthContext,
  options: AuthOptions,
): Promise<Record<string, unknown>> {
  for (const value of [...new Set(urls)]) {
    const url = await destination(value, "metadata", context, options);
    const response = await withinBudget(
      fetchChecked(
        url,
        {
          redirect: "error",
          ...(context.signal ? { signal: context.signal } : {}),
        },
        options,
      ),
      context.signal,
    );
    if (response.status === 404) continue;
    if (!response.ok) error("metadata request rejected");
    return record(await withinBudget(response.json(), context.signal));
  }
  return error("metadata unavailable");
}
function validateResource(
  value: string,
  endpoint: string,
  options: AuthOptions,
): void {
  const resource = secureUrl(value, options),
    target = secureUrl(endpoint, options);
  if (
    (value !== endpoint && resource.search !== "") ||
    resource.origin !== target.origin ||
    !(
      target.pathname === resource.pathname ||
      target.pathname.startsWith(resource.pathname.replace(/\/$/, "") + "/")
    )
  )
    error("resource does not cover endpoint");
}

const defaults: AuthProvider = {
  async credential(context) {
    const credential = await this.authenticate(context);
    if (credential?.expiresAt !== undefined &&
        (!Number.isFinite(credential.expiresAt) || credential.expiresAt <= Date.now()))
      throw new Error("Invalid authentication credential expiry");
    return credential === undefined ? undefined : { type: "bearer", token: credential.token };
  },
  // Step 0: a 401 drops the rejected access token first, so neither the replay nor a
  // later delivery resends it; refresh material survives. Then the challenge is decided
  // like every entry point; acting on it (renewal, login) is the replay's or the next call's.
  async challenge(context) {
    const status = context.response.status;
    if (status !== 401 && status !== 403) return;
    const rejected = context.credential?.token;
    if (status === 401 && rejected !== undefined && context.cache) {
      for (const [key, cached] of context.cache) {
        if (cached.token !== rejected) continue;
        if (cached.refreshToken) context.cache.set(key, { ...cached, expiresAt: 0 });
        else context.cache.delete(key);
      }
    }
    const binding = context.authentication as { type?: unknown } | undefined;
    if (binding && binding.type !== "oauth") return;
    const header = context.response.headers.get("www-authenticate") ?? undefined;
    const challenged: AuthContext = { ...context, challenged: true, challengeStatus: status,
      ...(header === undefined ? {} : { challenge: header }) };
    const options = context.authOptions ?? {};
    const discoveryKey = JSON.stringify([context.url, context.authentication ?? null]);
    const known = context.discoveryCache?.get(discoveryKey);
    if (!known) {
      // No I/O here: the replay (or next call) discovers the client and decides fully.
      // The challenge's own form is decided now, so an unreplayed request still fails.
      // decide without a known client: only its challenge-form refusal (step 2) for an
      // unparseable challenge or a 403 other than insufficient_scope applies now.
      const form = legacyChallenge(challenged);
      const { outcome } = decide({ op: "challenge", config: { flow: "authorization_code_pkce", requested: [] }, challenge: form });
      if (outcome.type === "fail" && outcome.step === 2 && (form.kind === "invalid" || form.kind === "forbidden")) throw outcome.error;
      return;
    }
    const { client } = known;
    const cached = await withinBudget(Promise.resolve(this.getToken(cacheKey(context, client), context)), context.signal);
    const now = (options.now ?? Date.now)();
    const op: DecisionOperation = options.authorize ? "prepare" : "challenge";
    const { outcome } = decide({ op, config: legacyConfig(client, context), challenge: legacyChallenge(challenged), sent: rejected,
      grant: cached ? { generation: cached.token, granted: cached.scopes ?? [], refresh: cached.refreshToken !== undefined,
        tokenValid: cached.expiresAt === undefined || cached.expiresAt > now + (options.expirySkewMs ?? 30_000) } : undefined });
    if (outcome.type === "fail") throw outcome.error;
  },
  getToken(key, context) {
    return context.cache?.get(key);
  },
  setToken(key, credential, context) {
    (context.cache ?? (context.cache = new Map())).set(key, credential);
  },
  deleteToken(key, context) {
    context.cache?.delete(key);
  },
  resolveEnvironmentVariable(name) {
    return (
      globalThis as { process?: { env?: Record<string, string | undefined> } }
    ).process?.env?.[name];
  },
  resolveCredentialReference() {
    return undefined;
  },
  async discover(context, options = {}) {
    const binding = context.authentication as
      | Record<string, unknown>
      | undefined;
    const endpoint = secureUrl(context.url, options);
    let client: OAuthClient;
    let resource: string;
    if (binding?.type === "oauth") {
      const flow = binding.flow;
      if (flow !== "authorization_code_pkce" && flow !== "client_credentials")
        error("unsupported OAuth flow");
      client = {
        issuer: string(binding.issuer, "issuer"),
        resource: string(binding.resource, "resource"),
        clientId: string(binding.clientId, "clientId"),
        flow,
        ...(binding.scopes !== undefined
          ? { scopes: strings(binding.scopes) }
          : {}),
        ...(binding.clientSecretRef !== undefined
          ? {
              clientSecretRef: string(
                binding.clientSecretRef,
                "clientSecretRef",
              ),
            }
          : {}),
      };
      resource = client.resource;
    } else {
      const advertised = challengeParameter(
        context.challenge,
        "resource_metadata",
      );
      const metadata = await metadataAt(
        advertised
          ? [advertised]
          : [
              `${endpoint.origin}/.well-known/oauth-protected-resource${endpoint.pathname === "/" ? "" : endpoint.pathname}`,
              `${endpoint.origin}/.well-known/oauth-protected-resource`,
            ],
        context,
        options,
      );
      resource = string(metadata.resource, "resource");
      validateResource(resource, context.url, options);
      const issuers = strings(metadata.authorization_servers);
      if (issuers.length === 0) error("authorization server missing");
      for (const issuer of issuers) secureUrl(issuer, options);
      if (!options.selectClient) error("OAuth client selection required");
      client = await withinBudget(
        Promise.resolve(options.selectClient(issuers, resource, context)),
        context.signal,
      );
      if (!issuers.includes(client.issuer) || client.resource !== resource)
        error("untrusted issuer or resource");
    }
    validateResource(resource, context.url, options);
    const issuer = secureUrl(client.issuer, options);
    if (issuer.search) error("invalid issuer");
    // Pre-registered clients only: without the managed store, coordination and secret
    // hook, this provider never uses CIMD or registers, so no client is unavailable.
    if (!client.clientId) throw new AuthError("credential_unavailable");
    if (!["authorization_code_pkce", "client_credentials"].includes(client.flow))
      error("invalid client configuration");
    // decide steps 1-4 before any issuer metadata I/O. The returned (and cached) client
    // keeps only host policy: a step-up requirement is operation-scoped.
    legacyGate(client, context);
    const path =
      issuer.pathname === "/" ? "" : issuer.pathname.replace(/\/$/, "");
    const discovered = await metadataAt(
      [
        `${issuer.origin}/.well-known/oauth-authorization-server${path}`,
        `${issuer.origin}/.well-known/openid-configuration${path}`,
        `${issuer.origin}${path}/.well-known/openid-configuration`,
      ],
      context,
      options,
    );
    if (discovered.issuer !== client.issuer) error("issuer mismatch");
    const metadata: OAuthMetadata = {
      issuer: client.issuer,
      token_endpoint: string(discovered.token_endpoint, "token endpoint"),
      ...(discovered.authorization_endpoint !== undefined
        ? {
            authorization_endpoint: string(
              discovered.authorization_endpoint,
              "authorization endpoint",
            ),
          }
        : {}),
      ...(discovered.grant_types_supported !== undefined
        ? { grant_types_supported: strings(discovered.grant_types_supported) }
        : {}),
      ...(discovered.code_challenge_methods_supported !== undefined
        ? {
            code_challenge_methods_supported: strings(
              discovered.code_challenge_methods_supported,
            ),
          }
        : {}),
      ...(discovered.token_endpoint_auth_methods_supported !== undefined
        ? {
            token_endpoint_auth_methods_supported: strings(
              discovered.token_endpoint_auth_methods_supported,
            ),
          }
        : {}),
    };
    await destination(metadata.token_endpoint, "token", context, options);
    return { client, metadata };
  },
  async requestToken(context, request, options = {}) {
    const { client, metadata } = request;
    const parameters = new URLSearchParams(request.parameters);
    parameters.set("client_id", client.clientId);
    parameters.set("resource", client.resource);
    if (client.scopes?.length) parameters.set("scope", client.scopes.join(" "));
    const url = await destination(
      metadata.token_endpoint,
      "token",
      context,
      options,
    );
    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    };
    if (client.clientSecretRef) {
      const secret = await withinBudget(
        Promise.resolve(
          this.resolveCredentialReference(client.clientSecretRef, context),
        ),
        context.signal,
      );
      if (!secret) error("client secret unavailable");
      const methods = metadata.token_endpoint_auth_methods_supported ?? [
        "client_secret_basic",
      ];
      if (methods.includes("client_secret_basic")) {
        const encode = (value: string) =>
          new URLSearchParams({ v: value }).toString().slice(2);
        headers.authorization = `Basic ${btoa(`${encode(client.clientId)}:${encode(secret)}`)}`;
      } else if (methods.includes("client_secret_post"))
        parameters.set("client_secret", secret);
      else error("unsupported client authentication");
    } else if (
      metadata.token_endpoint_auth_methods_supported &&
      !metadata.token_endpoint_auth_methods_supported.includes("none")
    )
      error("client secret required");
    // Caller cancellation is honoured only before sending. The transfer (headers and
    // body) is bounded by its own timeout so a response is never cut off mid-read.
    context.signal?.throwIfAborted();
    const response = await fetchChecked(
      url,
      {
        method: "POST",
        headers,
        body: parameters,
        redirect: "error",
        signal: AbortSignal.timeout(TRANSFER_TIMEOUT_MS),
      },
      options,
    );
    if (!response.ok) {
      // Renewal errors (refresh, client credentials) and code-exchange errors, as in
      // managedOAuth. This provider uses pre-registered clients only, so invalid_client is
      // credential_unavailable. Nothing here carries scopes.
      const failure = await response.json().catch(() => undefined) as { error?: unknown } | undefined;
      const grant = parameters.get("grant_type");
      const code = failure?.error;
      if (code === "invalid_grant") {
        throw new AuthError(grant === "refresh_token" ? "refresh_rejected" : grant === "authorization_code" ? "interaction_required" : "credential_unavailable");
      }
      if (code === "invalid_client" || (code === "unauthorized_client" && grant !== "authorization_code")) throw new AuthError("credential_unavailable");
      throw new AuthError("provider_failed");
    }
    const body = record(await response.json());
    try {
      if (
        typeof body.token_type !== "string" ||
        body.token_type.toLowerCase() !== "bearer"
      )
        error("unsupported token type");
      if (body.resource !== undefined && body.resource !== client.resource)
        error("token resource mismatch");
      const expires = body.expires_in;
      if (expires !== undefined && !(typeof expires === "number"
        ? Number.isSafeInteger(expires) && expires > 0
        : typeof expires === "string" && /^[0-9]+$/.test(expires) && Number(expires) > 0 && Number.isSafeInteger(Number(expires))))
        error("invalid token expiry");
      // An absent, null or blank scope is omitted and inherits; any other value must
      // be a strict RFC 6749 scope list.
      const reported = responseScopes(body.scope);
      if (reported === null) error("invalid token scope");
      // Granted = response ∩ local ceiling; extra scopes are ignored, not an error.
      const ceiling = client.allowedScopes ?? client.scopes ?? [];
      const scopes = [...new Set(reported ?? client.scopes ?? [])]
        .filter(scope => ceiling.includes(scope));
      const credential = validateCredential(
        {
          token: string(body.access_token, "access token"),
          ...(expires !== undefined
            ? { expiresAt: (options.now ?? Date.now)() + Number(expires) * 1000 }
            : {}),
          ...(body.refresh_token !== undefined
            ? { refreshToken: string(body.refresh_token, "refresh token") }
            : {}),
          ...(scopes ? { scopes } : {}),
        },
        options,
      );
      if (reported === undefined) inheritedScopes.add(credential);
      return credential;
    } catch (failure) {
      // An invalid response is not dispatched, but a valid rotated refresh token is kept.
      const rotated = body.refresh_token;
      if (typeof rotated === "string" && rotated && !/[\s\x00-\x1f\x7f]/.test(rotated) && typeof failure === "object" && failure !== null)
        rotatedRefresh.set(failure, rotated);
      throw failure;
    }
  },
  async exchangeAuthorizationCode(request, context, options) {
    const parameters = new URLSearchParams(request.parameters);
    parameters.set("grant_type", "authorization_code");
    parameters.set("code", request.code);
    parameters.set("code_verifier", request.verifier);
    parameters.set("redirect_uri", request.redirectUri);
    return this.requestToken(context, { ...request, parameters }, options);
  },
  async refresh(context, request, refreshToken, options) {
    const parameters = new URLSearchParams(request.parameters);
    parameters.set("grant_type", "refresh_token");
    parameters.set("refresh_token", refreshToken);
    const credential = await this.requestToken(
      context,
      { ...request, parameters },
      options,
    );
    const refreshed = {
      ...credential,
      refreshToken: credential.refreshToken ?? refreshToken,
    };
    if (inheritedScopes.has(credential)) inheritedScopes.add(refreshed);
    return refreshed;
  },
  async clientCredentials(context, request, options) {
    if (!request.metadata.grant_types_supported?.includes("client_credentials"))
      error("client credentials not advertised");
    const parameters = new URLSearchParams(request.parameters);
    parameters.set("grant_type", "client_credentials");
    return this.requestToken(context, { ...request, parameters }, options);
  },
  async authenticate(context, options = {}) {
    context.signal?.throwIfAborted();
    const binding = context.authentication as
      | Record<string, unknown>
      | undefined;
    if (binding?.type === "bearer") {
      const env = binding.tokenEnv,
        ref = binding.tokenRef;
      if ((env !== undefined) === (ref !== undefined))
        error("bearer requires exactly one credential source");
      const token = await withinBudget(
        Promise.resolve(
          env !== undefined
            ? this.resolveEnvironmentVariable(string(env, "tokenEnv"), context)
            : this.resolveCredentialReference(string(ref, "tokenRef"), context),
        ),
        context.signal,
      );
      if (!token) throw new AuthError("credential_unavailable");
      return validateCredential({ token }, options);
    }
    if (binding && binding.type !== "oauth")
      error("unsupported authentication binding");
    const discoveryCache =
      context.discoveryCache ?? (context.discoveryCache = new Map());
    const discoveryKey = JSON.stringify([
      context.url,
      context.authentication ?? null,
    ]);
    const known = discoveryCache.get(discoveryKey);
    const challenged = context.challenged || context.challenge !== undefined;
    if (!binding && !challenged && !known) return undefined;
    const challenge = legacyChallenge(context);
    // An inline authorize hook makes this a sign-in (decide's prepare); otherwise PKCE
    // without a usable grant needs a login this call cannot create.
    const op: DecisionOperation = options.authorize ? "prepare" : "credential";
    // With a known client, decide steps 1-4 locally before any rediscovery; only a 401
    // rediscovers (honouring a resource_metadata hint).
    if (known) legacyGate(known.client, context);
    const discovered =
      known && challenge.status !== 401 ? known : await this.discover(context, options);
    const { client, metadata } = discovered;
    if (known && cacheKey(context, known.client) !== cacheKey(context, client))
      error("OAuth identity changed");
    const key = cacheKey(context, client);
    const cached = await withinBudget(
      Promise.resolve(this.getToken(key, context)),
      context.signal,
    );
    const now = (options.now ?? Date.now)();
    // The rejected token: the replay names it; a 401 otherwise rejects the cached token.
    const sent = context.rejectedCredential?.token ?? (challenge.status === 401 ? cached?.token : undefined);
    const ceiling = client.allowedScopes ?? client.scopes ?? [];
    const decision = decide({ op, config: legacyConfig(client, context), challenge, sent,
      grant: cached ? { generation: cached.token, granted: cached.scopes ?? [], refresh: cached.refreshToken !== undefined,
        tokenValid: cached.expiresAt === undefined || cached.expiresAt > now + (options.expirySkewMs ?? 30_000) } : undefined });
    const { outcome, required } = decision;
    if (outcome.type === "fail") throw outcome.error;
    if (outcome.type === "use") return validateCredential(cached!, options);
    // decide's request set (previous ∪ ((S ∪ R [∪ P′]) ∩ C)); recorded against previous ∪ C.
    const request: TokenRequest = {
      client: { ...client, requiredScopes: [...required],
        ...(outcome.type === "refresh" ? {} : { scopes: [...outcome.request] }),
        allowedScopes: [...new Set([...(cached?.scopes ?? []), ...ceiling])] },
      metadata,
      parameters: new URLSearchParams(),
    };
    // Once a token request is sent, receiving and persisting its response runs
    // detached from the caller's signal; the caller still gets its abort promptly.
    const commit = async (credential: Credential): Promise<Credential> => {
      validateCredential(credential, options);
      await Promise.resolve(this.setToken(key, credential, context));
      return credential;
    };
    let credential: Credential;
    if (outcome.type === "refresh" && cached?.refreshToken) {
      // Keep the record until the refresh succeeds or definitively fails; a
      // transient failure must not lose refresh material.
      const presented = cached.refreshToken;
      credential = await withinBudget((async () => {
        let refreshed: Credential;
        try {
          refreshed = await this.refresh(context, { ...request, client }, presented, options);
        } catch (failure) {
          const rotated = typeof failure === "object" && failure !== null ? rotatedRefresh.get(failure) : undefined;
          if ((failure instanceof AuthError && failure.code === "refresh_rejected") || rotated !== undefined) {
            // Compare-and-delete/replace: keep a newer record holding a different refresh token.
            const latest = await Promise.resolve(this.getToken(key, context));
            if (latest?.refreshToken === presented) {
              await Promise.resolve(rotated === undefined
                ? this.deleteToken(key, context)
                : this.setToken(key, { ...latest, refreshToken: rotated, expiresAt: 0 }, context));
            }
          }
          throw failure;
        }
        // Granted = response ∩ previous grant; an omitted response scope inherits it.
        if (cached.scopes && inheritedScopes.has(refreshed)) refreshed = { ...refreshed, scopes: [...cached.scopes] };
        else if (cached.scopes && refreshed.scopes)
          refreshed = { ...refreshed, scopes: refreshed.scopes.filter((scope: string) => cached.scopes!.includes(scope)) };
        return commit(refreshed);
      })(), context.signal);
    } else if (outcome.type === "acquire") {
      credential = await withinBudget(this.clientCredentials(context, request, options).then(commit), context.signal);
    } else {
      if (!options.authorize) error("interactive authorization unavailable");
      if (!metadata.code_challenge_methods_supported?.includes("S256"))
        error("PKCE S256 unavailable");
      if (
        metadata.grant_types_supported &&
        !metadata.grant_types_supported.includes("authorization_code")
      )
        error("authorization code not supported");
      const redirectUri = client.redirectUri ?? options.redirectUri;
      if (!redirectUri) error("redirect URI required");
      const redirect = new URL(redirectUri);
      if (
        redirect.username ||
        redirect.password ||
        redirect.hash ||
        !(
          redirect.protocol === "https:" ||
          (redirect.protocol === "http:" &&
            ["127.0.0.1", "[::1]"].includes(redirect.hostname))
        )
      )
        error("invalid redirect URI");
      if (
        redirect.searchParams.has("code") ||
        redirect.searchParams.has("state") ||
        redirect.searchParams.has("error")
      )
        error("reserved redirect parameter");
      const authorization = await destination(
        string(metadata.authorization_endpoint, "authorization endpoint"),
        "authorization",
        context,
        options,
      );
      const verifier = base64url(
        globalThis.crypto.getRandomValues(new Uint8Array(32)),
      );
      const state = base64url(
        globalThis.crypto.getRandomValues(new Uint8Array(32)),
      );
      const challenge = base64url(
        new Uint8Array(
          await globalThis.crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(verifier),
          ),
        ),
      );
      for (const [name, value] of Object.entries({
        response_type: "code",
        client_id: client.clientId,
        redirect_uri: redirectUri,
        resource: client.resource,
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
      }))
        authorization.searchParams.set(name, value);
      if (request.client.scopes?.length)
        authorization.searchParams.set("scope", request.client.scopes.join(" "));
      const callback = new URL(
        await withinBudget(
          Promise.resolve(
            options.authorize(
              {
                url: authorization.href,
                redirectUri,
                state,
                ...(context.signal ? { signal: context.signal } : {}),
              },
              context,
            ),
          ),
          context.signal,
        ),
      );
      if (
        callback.origin !== redirect.origin ||
        callback.pathname !== redirect.pathname ||
        callback.hash ||
        callback.username ||
        callback.password
      )
        error("redirect mismatch");
      for (const [name, value] of redirect.searchParams)
        if (callback.searchParams.get(name) !== value)
          error("redirect query mismatch");
      if (
        callback.searchParams.getAll("state").length !== 1 ||
        callback.searchParams.get("state") !== state
      )
        error("state mismatch");
      if (callback.searchParams.has("error")) error("authorization denied");
      if (
        callback.searchParams.has("iss") &&
        callback.searchParams.get("iss") !== client.issuer
      )
        error("authorization issuer mismatch");
      if (callback.searchParams.getAll("code").length !== 1)
        error("authorization code missing");
      credential = await withinBudget(this.exchangeAuthorizationCode(
        {
          ...request,
          code: string(callback.searchParams.get("code"), "authorization code"),
          verifier,
          redirectUri,
        },
        context,
        options,
      ).then(commit), context.signal);
    }
    // The cached client holds host policy only; R applied to this operation.
    discoveryCache.set(discoveryKey, discovered);
    const denied = coverage(required, credential.scopes ?? [], ceiling);
    if (denied) throw denied;
    return credential;
  },
};

/** Compose host-specific policy with SDK defaults; defaults remain callable for delegation. */
export const auth = Object.assign(
  function auth(overrides: AuthOptions = {}): AuthProvider {
    const provider = { ...defaults, ...overrides } as AuthProvider;
    // Each composed provider owns its fallback cache. Callers can supply endpoint-
    // scoped caches when sharing a provider; keys also include the full endpoint.
    const cache = new Map<string, Credential>();
    // Hooks can spread each context per request while retaining its token Map.
    // A WeakMap keyed by that Map isolates discovery across Hooks instances even
    // when they deliberately share this composed provider.
    const discoveryCaches = new WeakMap<
      Map<string, Credential>,
      NonNullable<AuthContext["discoveryCache"]>
    >();
    const authenticate = provider.authenticate;
    const challenge = provider.challenge;
    provider.challenge = async (context) => {
      const tokens = context.cache ?? cache;
      let discoveryCache = context.discoveryCache ?? discoveryCaches.get(tokens);
      if (!discoveryCache) { discoveryCache = new Map(); discoveryCaches.set(tokens, discoveryCache); }
      try {
        return await challenge.call(provider, { ...context, cache: tokens, discoveryCache, provider, authOptions: { ...overrides, ...context.authOptions } });
      } catch (error) { throw legacyClassify(error); }
    };
    provider.authenticate = async (context, options) => {
      const configured = { ...overrides, ...options };
      const tokens = context.cache ?? cache;
      let discoveryCache =
        context.discoveryCache ?? discoveryCaches.get(tokens);
      if (!discoveryCache) {
        discoveryCache = new Map();
        discoveryCaches.set(tokens, discoveryCache);
      }
      try {
        return await authenticate.call(
          provider,
          {
            ...context,
            cache: tokens,
            discoveryCache,
            provider,
            authOptions: configured,
          },
          configured,
        );
      } catch (error) { throw legacyClassify(error); }
    };
    return provider;
  },
  {
    ...defaults,
    /** Route independent bearer, OAuth and challenge-discovery providers. */
    compose(options: AuthCompositionOptions): DeliveryAuthProvider {
      return composeAuth(options, auth());
    },
    /** Bearer-only resolver for the bearer composition route; other bindings are unsupported. */
    bearer(options: Pick<AuthOptions, "resolveEnvironmentVariable" | "resolveCredentialReference"> = {}): DeliveryAuthProvider {
      const provider = auth(options);
      return {
        resolveEnvironmentVariable: provider.resolveEnvironmentVariable.bind(provider),
        resolveCredentialReference: provider.resolveCredentialReference.bind(provider),
        async credential(context) {
          if (context.authentication?.type !== "bearer") throw new AuthError("unsupported_binding");
          return provider.credential(context);
        },
        // Each attempt re-resolves the source, so there is no cached token to drop.
        challenge() {},
      };
    },
    authenticate(context: AuthContext, options?: AuthOptions) {
      return defaults.authenticate.call(context.provider ?? defaults, context, {
        ...context.authOptions,
        ...options,
      });
    },
    exchangeAuthorizationCode(
      request: AuthorizationCodeRequest,
      context: AuthContext,
      options?: AuthOptions,
    ) {
      return defaults.exchangeAuthorizationCode.call(
        context.provider ?? defaults,
        request,
        context,
        { ...context.authOptions, ...options },
      );
    },
    discover(context: AuthContext, options?: AuthOptions) {
      return defaults.discover.call(context.provider ?? defaults, context, {
        ...context.authOptions,
        ...options,
      });
    },
    requestToken(
      context: AuthContext,
      request: TokenRequest,
      options?: AuthOptions,
    ) {
      return defaults.requestToken.call(
        context.provider ?? defaults,
        context,
        request,
        { ...context.authOptions, ...options },
      );
    },
    refresh(
      context: AuthContext,
      request: TokenRequest,
      refreshToken: string,
      options?: AuthOptions,
    ) {
      return defaults.refresh.call(
        context.provider ?? defaults,
        context,
        request,
        refreshToken,
        { ...context.authOptions, ...options },
      );
    },
    clientCredentials(
      context: AuthContext,
      request: TokenRequest,
      options?: AuthOptions,
    ) {
      return defaults.clientCredentials.call(
        context.provider ?? defaults,
        context,
        request,
        { ...context.authOptions, ...options },
      );
    },
  },
);
