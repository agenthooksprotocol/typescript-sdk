import * as oauth from "oauth4webapi";
import { AuthError, classifyAuthError } from "../client/auth.js";
import { omittedScope, responseScopes } from "../client/scope.js";
import { active, checkedFetch, markTransport } from "./discovery.js";
export { isTransportFailure } from "./discovery.js";
import type { ManagedOAuthOptions, Operation, ResolvedTarget, TokenValue } from "./types.js";

/** A token response that was not dispatched still reports a valid rotated refresh token. */
export type TokenResult = { readonly value: TokenValue } | { readonly value?: undefined; readonly refreshToken?: string };

export interface LoginState {
  readonly authorizationUrl: string;
  readonly state: string;
  readonly verifier: string;
}

const invalidClients = new WeakSet<AuthError>();
/** A token or authorization endpoint `invalid_client` OAuth error, so the client itself was rejected. */
export function isInvalidClient(error: unknown): boolean {
  return error instanceof AuthError && invalidClients.has(error);
}

async function protect<T>(operation: Operation, work: () => Promise<T>, grant: "code" | "refresh" | "client_credentials" = "code"): Promise<T> {
  try {
    active(operation);
    // No signal check after the response: a received token response must reach the
    // caller's commit, or a rotated refresh token would be lost.
    return await work();
  } catch (error) {
    // A server OAuth error response is classified even after a caller abort, so the
    // caller of refresh can still compare-and-delete a rejected refresh token.
    if (!(error instanceof oauth.ResponseBodyError)) active(operation);
    const classified = classifyAuthError(error);
    if (classified.code !== "provider_failed") throw classified;
    if (error instanceof oauth.ResponseBodyError || error instanceof oauth.AuthorizationResponseError) {
      if (error.error === "invalid_client") {
        const rejected = new AuthError("credential_unavailable");
        invalidClients.add(rejected);
        throw rejected;
      }
      if (error.error === "unauthorized_client") throw new AuthError("credential_unavailable");
      if (error.error === "access_denied") throw new AuthError("access_denied");
      if (error.error === "invalid_grant") {
        throw new AuthError(grant === "refresh" ? "refresh_rejected" : grant === "code" ? "interaction_required" : "credential_unavailable");
      }
    }
    if (error instanceof oauth.UnsupportedOperationError ||
        (error instanceof oauth.OperationProcessingError &&
         (error.code === oauth.MISSING_SERVER_METADATA || error.code === oauth.INVALID_SERVER_METADATA))) {
      throw new AuthError("unsupported_binding");
    }
    throw classified;
  }
}

function client(target: ResolvedTarget): oauth.Client {
  return { client_id: target.client.clientId! };
}

function authentication(target: ResolvedTarget): oauth.ClientAuth {
  const supported = target.metadata.token_endpoint_auth_methods_supported ?? ["client_secret_basic"];
  // A registered client authenticates with the method it was registered for.
  if (target.authMethod !== undefined && target.client.clientSecret) {
    return target.authMethod === "client_secret_post" ? oauth.ClientSecretPost(target.client.clientSecret)
      : oauth.ClientSecretBasic(target.client.clientSecret);
  }
  if (target.client.clientSecret) {
    if (supported.includes("client_secret_basic")) return oauth.ClientSecretBasic(target.client.clientSecret);
    if (supported.includes("client_secret_post")) return oauth.ClientSecretPost(target.client.clientSecret);
  } else if (target.client.flow !== "client_credentials" && supported.includes("none")) {
    return oauth.None();
  }
  throw new AuthError("unsupported_binding");
}

function requestOptions(options: ManagedOAuthOptions, operation: Operation): oauth.TokenEndpointRequestOptions {
  return {
    // checkedFetch replaces this with the transfer signal once the request is sent.
    [oauth.customFetch]: (url, init) => checkedFetch(url, init, "token", options, operation),
  };
}

function safeToken(value: string): boolean {
  return value.length > 0 && !/[\s\x00-\x1f\x7f-\x9f]/u.test(value);
}

/**
 * Initial exchange: granted = response ∩ acquisition ceiling. Refresh: granted =
 * response ∩ previous grant (the current ceiling applies only at use). Extra
 * scopes are ignored, never an error. An absent, null or blank scope is omitted.
 */
function parseToken(body: unknown, target: ResolvedTarget, previous?: readonly string[]): TokenResult {
  const json = typeof body === "object" && body !== null ? body as Record<string, unknown> : {};
  const refresh = json.refresh_token;
  const refreshToken = typeof refresh === "string" && safeToken(refresh) ? refresh : undefined;
  const expires = json.expires_in;
  const type = typeof json.token_type === "string" ? json.token_type.toLowerCase() : undefined;
  const granted = responseScopes(json.scope);
  if (type !== "bearer" || typeof json.access_token !== "string" || !/^[A-Za-z0-9\-._~+/]+=*$/.test(json.access_token) ||
      (expires !== undefined && !(typeof expires === "number" ? Number.isSafeInteger(expires) && expires > 0
        : typeof expires === "string" && /^[0-9]+$/.test(expires) && Number(expires) > 0 && Number.isSafeInteger(Number(expires)))) ||
      granted === null ||
      (refresh !== undefined && refreshToken === undefined)) {
    return refreshToken === undefined ? {} : { refreshToken };
  }
  const bound = previous ?? target.client.allowedScopes ?? target.client.scopes;
  const response = granted ?? previous ?? target.client.scopes;
  const scopes = [...new Set(response)].filter(scope => bound.includes(scope));
  return { value: {
    token: json.access_token, scopes,
    ...(expires === undefined ? {} : { expiresAt: Date.now() + Number(expires) * 1000 }),
    ...(refreshToken === undefined ? {} : { refreshToken }),
  } };
}

function rawBody(text: string): Record<string, unknown> | undefined {
  try {
    const json: unknown = JSON.parse(text);
    if (typeof json === "object" && json !== null && !Array.isArray(json)) return json as Record<string, unknown>;
  } catch { /* Not JSON: try a form body. */ }
  const form = new URLSearchParams(text);
  return form.has("refresh_token") || form.has("access_token") ? Object.fromEntries(form) : undefined;
}

/** oauth4webapi rejects a JSON null `scope`; an omitted-equivalent scope is removed
 * before processing so that it inherits like an absent one. */
function withoutOmittedScope(response: Response, text: string | undefined): Response {
  if (text === undefined) return response;
  let json: unknown;
  try { json = JSON.parse(text); } catch { return response; }
  if (typeof json !== "object" || json === null || Array.isArray(json) || !Object.hasOwn(json, "scope") ||
      !omittedScope((json as { scope?: unknown }).scope)) return response;
  const { scope: _omitted, ...rest } = json as Record<string, unknown>;
  return new Response(JSON.stringify(rest), { status: response.status, statusText: response.statusText, headers: response.headers });
}

async function tokenResult(response: Response, target: ResolvedTarget,
  process: (response: Response) => Promise<unknown>, previous?: readonly string[]): Promise<TokenResult> {
  // Capture the body of any 2xx, whatever its content type, so a rotated refresh
  // token survives a response the OAuth library rejects.
  const text = response.status >= 200 && response.status < 300 ? await response.clone().text().catch(() => "") : undefined;
  const raw = text === undefined ? undefined : rawBody(text);
  let body: unknown;
  try { body = await process(withoutOmittedScope(response, text)); }
  catch (error) {
    // OAuth error responses are classified by protect(); anything else is an invalid response.
    if (error instanceof oauth.ResponseBodyError) throw error;
    if (raw === undefined) {
      // Only 404/410 prove the endpoint did not process the request (moved). Anything
      // else after sending (5xx, non-OAuth body) is ambiguous: never refetch or retry.
      const moved = response.status === 404 || response.status === 410;
      throw moved ? markTransport(new AuthError("provider_failed")) : new AuthError("provider_failed");
    }
    return parseToken({ ...raw as object, token_type: "invalid" }, target);
  }
  // Validate the server's own expires_in, not oauth4webapi's parseFloat coercion.
  const expires = (raw as { expires_in?: unknown } | undefined)?.expires_in;
  return parseToken({ ...body as object, expires_in: expires }, target, previous);
}

function literalLoopback(authority: string, hostname: string): boolean {
  if (/^\[[0-9a-f:]+\](?::[0-9]+)?$/i.test(authority)) return hostname === "[::1]";
  const raw = /^([^:]+)(?::[0-9]+)?$/.exec(authority)?.[1];
  if (raw === undefined) return false;
  const octets = raw.split(".");
  return octets.length === 4 && octets[0] === "127" &&
    octets.every(octet => /^(?:0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255);
}

/** An `http` redirect to a literal loopback IP without userinfo, whose port may vary per login. */
export function loopbackRedirect(uri: string): URL | undefined {
  let url: URL;
  try { url = new URL(uri); } catch { return undefined; }
  const authority = /^[a-z]+:\/\/([^/?#]*)/i.exec(uri)?.[1] ?? "";
  return url.protocol === "http:" && !url.username && !url.password && !authority.includes("@") &&
    literalLoopback(authority, url.hostname) ? url : undefined;
}

/** HTTPS, or HTTP only to a literal loopback IP (RFC 8252): `localhost` is invalid_configuration. */
export function checkRedirect(redirectUri: string | undefined): void {
  if (!redirectUri || typeof redirectUri !== "string" || !/^https?:\/\//i.test(redirectUri) ||
      /[\s\x00-\x1f\x7f-\x9f]/u.test(redirectUri) || redirectUri.includes("#")) {
    throw new AuthError("invalid_configuration");
  }
  let redirect: URL;
  try { redirect = new URL(redirectUri); } catch { throw new AuthError("invalid_configuration"); }
  const authority = /^[a-z]+:\/\/([^/?#]*)/i.exec(redirectUri)?.[1] ?? "";
  if (redirect.username || redirect.password || authority.includes("@") || redirectUri.includes("\\") ||
      (redirect.protocol !== "https:" &&
       !(redirect.protocol === "http:" && literalLoopback(authority, redirect.hostname))) ||
      ["code", "state", "error", "iss"].some(key => redirect.searchParams.has(key))) {
    throw new AuthError("invalid_configuration");
  }
}

export function pkce(target: ResolvedTarget): void {
  if (target.client.flow !== "authorization_code_pkce" ||
      !target.metadata.code_challenge_methods_supported?.includes("S256") ||
      (target.metadata.grant_types_supported !== undefined &&
       !target.metadata.grant_types_supported.includes("authorization_code")) ||
      (target.metadata.response_types_supported !== undefined &&
       !target.metadata.response_types_supported.includes("code"))) {
    throw new AuthError("unsupported_binding");
  }
  checkRedirect(target.client.redirectUri);
}

export function startLogin(target: ResolvedTarget, options: ManagedOAuthOptions, operation: Operation): Promise<LoginState> {
  return protect(operation, async () => {
    pkce(target);
    authentication(target);
    if (!target.metadata.authorization_endpoint) throw new AuthError("unsupported_binding");
    const url = new URL(target.metadata.authorization_endpoint);
    if (url.protocol !== "https:" || url.username || url.password || url.hash) throw new AuthError("untrusted_destination");
    const state = oauth.generateRandomState();
    const verifier = oauth.generateRandomCodeVerifier();
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", target.client.clientId!);
    url.searchParams.set("redirect_uri", target.client.redirectUri!);
    url.searchParams.set("scope", target.client.scopes.join(" "));
    url.searchParams.set("resource", target.client.resource);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", await oauth.calculatePKCECodeChallenge(verifier));
    url.searchParams.set("code_challenge_method", "S256");
    const approved = url.href;
    try {
      await options.checkDestination(url, "authorization", operation);
      if (url.href !== approved) throw new AuthError("untrusted_destination");
    } catch (error) {
      operation.signal.throwIfAborted();
      throw classifyAuthError(error, "untrusted_destination");
    }
    return { authorizationUrl: approved, state, verifier };
  });
}

export function callbackParameters(target: ResolvedTarget, login: LoginState, callback: string): URLSearchParams {
  const expected = new URL(target.client.redirectUri!);
  const actual = new URL(callback);
  if (actual.origin !== expected.origin || actual.pathname !== expected.pathname ||
      actual.username !== expected.username || actual.password !== expected.password || actual.hash || expected.hash) {
    throw new AuthError("access_denied");
  }
  for (const key of new Set(expected.searchParams.keys())) {
    const wanted = expected.searchParams.getAll(key);
    const received = actual.searchParams.getAll(key);
    if (wanted.length !== received.length || wanted.some((value, index) => value !== received[index])) {
      throw new AuthError("access_denied");
    }
  }
  if (actual.searchParams.has("iss") && actual.searchParams.get("iss") !== target.metadata.issuer) {
    throw new AuthError("access_denied");
  }
  if (!login.state || !login.verifier || actual.searchParams.getAll("state").length !== 1 ||
      actual.searchParams.get("state") !== login.state || actual.searchParams.getAll("iss").length > 1) throw new AuthError("access_denied");
  let parameters: URLSearchParams;
  try {
    parameters = oauth.validateAuthResponse(target.metadata, client(target), actual, login.state);
  } catch (error) {
    if (error instanceof oauth.AuthorizationResponseError) throw error;
    throw new AuthError("access_denied");
  }
  // A success response carries exactly one non-empty code, checked before the login is claimed.
  const codes = actual.searchParams.getAll("code");
  if (codes.length !== 1 || !codes[0]) throw new AuthError("access_denied");
  return parameters;
}

/** Return whether a correctly bound callback denies authorization. */
export function validateCallback(target: ResolvedTarget, login: LoginState, callback: string): boolean {
  try { callbackParameters(target, login, callback); return false; }
  catch (error) {
    if (error instanceof oauth.AuthorizationResponseError) return true;
    throw error;
  }
}

export function exchangeCode(target: ResolvedTarget, login: LoginState, callback: string,
  options: ManagedOAuthOptions, operation: Operation): Promise<TokenResult> {
  return protect(operation, async () => {
    pkce(target);
    const parameters = callbackParameters(target, login, callback);
    const response = await oauth.authorizationCodeGrantRequest(target.metadata, client(target), authentication(target),
      parameters, target.client.redirectUri!, login.verifier, {
        ...requestOptions(options, operation), additionalParameters: { resource: target.client.resource },
      });
    return tokenResult(response, target, r => oauth.processAuthorizationCodeResponse(target.metadata, client(target), r));
  });
}

export function acquireClientCredentials(target: ResolvedTarget, options: ManagedOAuthOptions,
  operation: Operation): Promise<TokenValue> {
  return protect(operation, async () => {
    if (target.client.flow !== "client_credentials" ||
        !target.metadata.grant_types_supported?.includes("client_credentials")) throw new AuthError("unsupported_binding");
    const response = await oauth.clientCredentialsGrantRequest(target.metadata, client(target), authentication(target),
      { resource: target.client.resource, scope: target.client.scopes.join(" ") }, requestOptions(options, operation));
    const result = await tokenResult(response, target, r => oauth.processClientCredentialsResponse(target.metadata, client(target), r));
    if (!result.value) throw new AuthError("provider_failed");
    return result.value;
  }, "client_credentials");
}

/** `previous` is the recorded prior grant: a refresh can narrow it but never broaden it. */
export function refreshCredential(target: ResolvedTarget, refreshToken: string, previous: readonly string[],
  options: ManagedOAuthOptions, operation: Operation): Promise<TokenResult> {
  return protect(operation, async () => {
    if (!safeToken(refreshToken)) throw new AuthError("refresh_rejected");
    if (target.metadata.grant_types_supported !== undefined &&
        !target.metadata.grant_types_supported.includes("refresh_token")) throw new AuthError("unsupported_binding");
    const response = await oauth.refreshTokenGrantRequest(target.metadata, client(target), authentication(target), refreshToken, {
      ...requestOptions(options, operation),
      additionalParameters: { resource: target.client.resource, ...(previous.length ? { scope: previous.join(" ") } : {}) },
    });
    return tokenResult(response, target, r => oauth.processRefreshTokenResponse(target.metadata, client(target), r), previous);
  }, "refresh");
}
