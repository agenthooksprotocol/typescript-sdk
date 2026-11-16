import * as oauth from "oauth4webapi";
import { AuthError } from "agenthooksprotocol/client/auth";
import { checkedFetch } from "./discovery.js";
import type { ManagedOAuthOptions, Operation, ResolvedTarget, TokenValue } from "./types.js";

export interface LoginState {
  readonly authorizationUrl: string;
  readonly state: string;
  readonly verifier: string;
}

function active(operation: Operation): void {
  operation.signal.throwIfAborted();
  if (Date.now() >= operation.deadline) throw new AuthError("provider_failed");
}

async function protect<T>(operation: Operation, work: () => Promise<T>, refresh = false): Promise<T> {
  try {
    active(operation);
    const result = await work();
    active(operation);
    return result;
  } catch (error) {
    operation.signal.throwIfAborted();
    if (error instanceof AuthError) throw error;
    if (error instanceof oauth.ResponseBodyError || error instanceof oauth.AuthorizationResponseError) {
      if (error.error === "access_denied") throw new AuthError("access_denied");
      if (refresh && error.error === "invalid_grant") throw new AuthError("refresh_rejected");
    }
    if (error instanceof oauth.UnsupportedOperationError ||
        (error instanceof oauth.OperationProcessingError &&
         (error.code === oauth.MISSING_SERVER_METADATA || error.code === oauth.INVALID_SERVER_METADATA))) {
      throw new AuthError("unsupported_binding");
    }
    throw new AuthError("provider_failed");
  }
}

function client(target: ResolvedTarget): oauth.Client {
  return { client_id: target.client.clientId };
}

function authentication(target: ResolvedTarget): oauth.ClientAuth {
  const supported = target.metadata.token_endpoint_auth_methods_supported ?? ["client_secret_basic"];
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
    signal: operation.signal,
    [oauth.customFetch]: (url, init) => checkedFetch(url, init, "token", options, operation),
  };
}

function safeToken(value: string): boolean {
  return value.length > 0 && !/[\s\x00-\x1f\x7f-\x9f]/u.test(value);
}

function tokenValue(response: oauth.TokenEndpointResponse, target: ResolvedTarget): TokenValue {
  const expires = response.expires_in;
  const scopes = response.scope === undefined ? [...target.client.scopes] : response.scope.split(" ");
  const allowed = new Set(target.client.scopes);
  if (response.token_type !== "bearer" || !/^[A-Za-z0-9\-._~+/]+=*$/.test(response.access_token) ||
      typeof expires !== "number" || !Number.isFinite(expires) || expires <= 0 ||
      (response.scope !== undefined && !/^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/.test(response.scope)) ||
      scopes.some(scope => !allowed.has(scope)) ||
      target.client.scopes.some(scope => !scopes.includes(scope)) ||
      (response.refresh_token !== undefined && !safeToken(response.refresh_token))) {
    throw new AuthError("provider_failed");
  }
  const expiresAt = Date.now() + expires * 1000;
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new AuthError("provider_failed");
  return {
    token: response.access_token, expiresAt, scopes: [...new Set(scopes)],
    ...(response.refresh_token === undefined ? {} : { refreshToken: response.refresh_token }),
  };
}

function pkce(target: ResolvedTarget): void {
  if (target.client.flow !== "authorization_code_pkce" ||
      !target.metadata.code_challenge_methods_supported?.includes("S256") ||
      (target.metadata.grant_types_supported !== undefined &&
       !target.metadata.grant_types_supported.includes("authorization_code")) ||
      (target.metadata.response_types_supported !== undefined &&
       !target.metadata.response_types_supported.includes("code"))) {
    throw new AuthError("unsupported_binding");
  }
  const redirectUri = target.client.redirectUri;
  if (!redirectUri || !/^https?:\/\//i.test(redirectUri) ||
      /[\s\x00-\x1f\x7f-\x9f]/u.test(redirectUri) || redirectUri.includes("#")) {
    throw new AuthError("invalid_configuration");
  }
  let redirect: URL;
  try { redirect = new URL(redirectUri); } catch { throw new AuthError("invalid_configuration"); }
  const authority = /^[a-z]+:\/\/([^/?#]*)/i.exec(redirectUri)?.[1] ?? "";
  if (redirect.username || redirect.password || authority.includes("@") || redirectUri.includes("\\") ||
      (redirect.protocol !== "https:" &&
       !(redirect.protocol === "http:" && /^(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?$/i.test(authority))) ||
      ["code", "state", "error", "iss"].some(key => redirect.searchParams.has(key))) {
    throw new AuthError("invalid_configuration");
  }
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
    url.searchParams.set("client_id", target.client.clientId);
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
    } catch {
      operation.signal.throwIfAborted();
      throw new AuthError("untrusted_destination");
    }
    return { authorizationUrl: approved, state, verifier };
  });
}

function callbackParameters(target: ResolvedTarget, login: LoginState, callback: string): URLSearchParams {
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
  if (!login.state || !login.verifier) throw new AuthError("access_denied");
  try {
    return oauth.validateAuthResponse(target.metadata, client(target), actual, login.state);
  } catch (error) {
    if (error instanceof oauth.AuthorizationResponseError) throw error;
    throw new AuthError("access_denied");
  }
}

export function exchangeCode(target: ResolvedTarget, login: LoginState, callback: string,
  options: ManagedOAuthOptions, operation: Operation): Promise<TokenValue> {
  return protect(operation, async () => {
    pkce(target);
    const parameters = callbackParameters(target, login, callback);
    const response = await oauth.authorizationCodeGrantRequest(target.metadata, client(target), authentication(target),
      parameters, target.client.redirectUri!, login.verifier, {
        ...requestOptions(options, operation), additionalParameters: { resource: target.client.resource },
      });
    return tokenValue(await oauth.processAuthorizationCodeResponse(target.metadata, client(target), response), target);
  });
}

export function acquireClientCredentials(target: ResolvedTarget, options: ManagedOAuthOptions,
  operation: Operation): Promise<TokenValue> {
  return protect(operation, async () => {
    if (target.client.flow !== "client_credentials" ||
        !target.metadata.grant_types_supported?.includes("client_credentials")) throw new AuthError("unsupported_binding");
    const response = await oauth.clientCredentialsGrantRequest(target.metadata, client(target), authentication(target),
      { resource: target.client.resource, scope: target.client.scopes.join(" ") }, requestOptions(options, operation));
    return tokenValue(await oauth.processClientCredentialsResponse(target.metadata, client(target), response), target);
  });
}

export function refreshCredential(target: ResolvedTarget, refreshToken: string, options: ManagedOAuthOptions,
  operation: Operation): Promise<TokenValue> {
  return protect(operation, async () => {
    if (!safeToken(refreshToken)) throw new AuthError("refresh_rejected");
    if (target.metadata.grant_types_supported !== undefined &&
        !target.metadata.grant_types_supported.includes("refresh_token")) throw new AuthError("unsupported_binding");
    const response = await oauth.refreshTokenGrantRequest(target.metadata, client(target), authentication(target), refreshToken, {
      ...requestOptions(options, operation),
      additionalParameters: { resource: target.client.resource, scope: target.client.scopes.join(" ") },
    });
    return tokenValue(await oauth.processRefreshTokenResponse(target.metadata, client(target), response), target);
  }, true);
}
