import type { Authentication } from "../draft/generated.js";

export interface Credential {
  token: string;
  /** Absolute expiry in milliseconds since the Unix epoch. */
  expiresAt?: number;
  refreshToken?: string;
  scopes?: string[];
}
export type AuthCredential = Credential;

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
  /** Set on a 401 even when WWW-Authenticate is absent. */
  challenged?: boolean;
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
  /** Undefined means no credential; configured authentication must fail closed. */
  credential(
    context: DeliveryAuthContext,
  ): DeliveryCredential | undefined | Promise<DeliveryCredential | undefined>;
  /**
   * Record a rejection before credentials are requested again. This does not
   * authorize replay: Hooks decides whether a bounded retry is protocol-safe.
   */
  challenge(context: AuthChallengeContext): void | Promise<void>;
}

export interface OAuthClient {
  issuer: string;
  resource: string;
  clientId: string;
  flow: "authorization_code_pkce" | "client_credentials";
  scopes?: string[];
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
export interface AuthProvider {
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
export type AuthOverrides = AuthOptions;

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
function publicAddress(address: string): boolean {
  const host = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (host.includes(":"))
    return (
      /^[23][\da-f]{3}:/.test(host) && !/^(?:2001:(?:db8|0):|2002:)/.test(host)
    );
  const octets = host.split(".").map(Number);
  if (
    octets.length !== 4 ||
    octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)
  )
    return false;
  const [a = 0, b = 0, c = 0] = octets;
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
function base64url(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function challengeParameter(
  challenge: string | undefined,
  name: string,
): string | undefined {
  if (!challenge) return undefined;
  const bearer = /(?:^|,)\s*Bearer\s+/i.exec(challenge);
  if (!bearer) return undefined;
  const tail = challenge.slice(bearer.index + bearer[0].length);
  // Tokenize quoted parameters (commas inside quoted strings are not separators).
  const parameters = tail.match(/(?:[^,"]|"(?:\\.|[^"\\])*")+/g) ?? [];
  for (const parameter of parameters) {
    const match =
      /^\s*([\w-]+)\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^,\s]+))\s*$/.exec(
        parameter,
      );
    if (!match) break; // Another authentication scheme begins here.
    if (match[1]?.toLowerCase() === name.toLowerCase())
      return (match[2] ?? match[3] ?? "").replace(/\\(.)/g, "$1");
  }
  return undefined;
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
    resource.search ||
    resource.origin !== target.origin ||
    !(
      target.pathname === resource.pathname ||
      target.pathname.startsWith(resource.pathname.replace(/\/$/, "") + "/")
    )
  )
    error("resource does not cover endpoint");
}

const defaults: AuthProvider = {
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
      if (
        metadata.resource !== resource ||
        !strings(metadata.authorization_servers).includes(client.issuer)
      )
        error("preset constraints violated");
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
    if (
      !client.clientId ||
      !["authorization_code_pkce", "client_credentials"].includes(client.flow)
    )
      error("invalid client configuration");
    const requiredScopes =
      challengeParameter(context.challenge, "scope")
        ?.split(/\s+/)
        .filter(Boolean) ?? [];
    if (requiredScopes.some((scope) => !(client.scopes ?? []).includes(scope)))
      error("challenge exceeds permitted scopes");
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
    const response = await withinBudget(
      fetchChecked(
        url,
        {
          method: "POST",
          headers,
          body: parameters,
          redirect: "error",
          ...(context.signal ? { signal: context.signal } : {}),
        },
        options,
      ),
      context.signal,
    );
    if (!response.ok) error("token request rejected");
    const body = record(await withinBudget(response.json(), context.signal));
    if (
      typeof body.token_type !== "string" ||
      body.token_type.toLowerCase() !== "bearer"
    )
      error("unsupported token type");
    if (body.resource !== undefined && body.resource !== client.resource)
      error("token resource mismatch");
    if (
      body.expires_in !== undefined &&
      (typeof body.expires_in !== "number" ||
        !Number.isFinite(body.expires_in) ||
        body.expires_in <= 0)
    )
      error("invalid token expiry");
    const scopes =
      body.scope === undefined
        ? client.scopes
        : string(body.scope, "scope").split(/\s+/);
    if (
      scopes?.some((scope) => !(client.scopes ?? []).includes(scope)) ||
      client.scopes?.some((scope) => !scopes?.includes(scope))
    )
      error("token scope mismatch");
    return validateCredential(
      {
        token: string(body.access_token, "access token"),
        ...(typeof body.expires_in === "number"
          ? { expiresAt: (options.now ?? Date.now)() + body.expires_in * 1000 }
          : {}),
        ...(body.refresh_token !== undefined
          ? { refreshToken: string(body.refresh_token, "refresh token") }
          : {}),
        ...(scopes ? { scopes } : {}),
      },
      options,
    );
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
    return {
      ...credential,
      refreshToken: credential.refreshToken ?? refreshToken,
    };
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
      if (!token) error("bearer credential unavailable");
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
    const discovered =
      known && !challenged ? known : await this.discover(context, options);
    const { client, metadata } = discovered;
    if (known && cacheKey(context, known.client) !== cacheKey(context, client))
      error("OAuth identity changed");
    const key = cacheKey(context, client);
    const cached = await withinBudget(
      Promise.resolve(this.getToken(key, context)),
      context.signal,
    );
    const now = (options.now ?? Date.now)();
    if (
      cached &&
      !context.challenged &&
      context.challenge === undefined &&
      (cached.expiresAt === undefined ||
        cached.expiresAt > now + (options.expirySkewMs ?? 30_000))
    )
      return validateCredential(cached, options);
    const request: TokenRequest = {
      client,
      metadata,
      parameters: new URLSearchParams(),
    };
    let credential: Credential;
    if (cached?.refreshToken) {
      await withinBudget(
        Promise.resolve(this.deleteToken(key, context)),
        context.signal,
      );
      credential = await this.refresh(
        context,
        request,
        cached.refreshToken,
        options,
      );
    } else if (client.flow === "client_credentials") {
      credential = await this.clientCredentials(context, request, options);
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
      if (client.scopes?.length)
        authorization.searchParams.set("scope", client.scopes.join(" "));
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
      credential = await this.exchangeAuthorizationCode(
        {
          ...request,
          code: string(callback.searchParams.get("code"), "authorization code"),
          verifier,
          redirectUri,
        },
        context,
        options,
      );
    }
    validateCredential(credential, options);
    await withinBudget(
      Promise.resolve(this.setToken(key, credential, context)),
      context.signal,
    );
    discoveryCache.set(discoveryKey, discovered);
    return credential;
  },
};

/** Compose host-specific policy with SDK defaults; defaults remain callable for delegation. */
export const auth = Object.assign(
  function auth(overrides: AuthOverrides = {}): AuthProvider {
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
    provider.authenticate = (context, options) => {
      const configured = { ...overrides, ...options };
      const tokens = context.cache ?? cache;
      let discoveryCache =
        context.discoveryCache ?? discoveryCaches.get(tokens);
      if (!discoveryCache) {
        discoveryCache = new Map();
        discoveryCaches.set(tokens, discoveryCache);
      }
      return authenticate.call(
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
    };
    return provider;
  },
  {
    ...defaults,
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
