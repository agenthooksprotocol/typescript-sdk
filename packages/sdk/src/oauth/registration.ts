import { AuthError, classifyAuthError } from "../client/auth.js";
import { active, https } from "./discovery.js";
import { checkRedirect, loopbackRedirect } from "./protocol.js";
import type { ClientConfig, ClientSelection, ClientSource, ManagedOAuthOptions, Operation } from "./types.js";

/** Canonical UTF-8 framed SDK storage identity. */
export function frame(prefix: string, fields: readonly string[]): string {
  const encoder = new TextEncoder();
  return prefix + fields.map(value => `${encoder.encode(value).length}:${value}`).join("");
}
/** The client-credentials registration shared by every client-credentials grant in a namespace at one issuer. */
export function registrationKey(namespace: string, issuer: string): string {
  return frame("ahp.oauth.registration:", [namespace, issuer]);
}
export function failureKey(registration: string): string {
  return frame("ahp.oauth.registration-failure:", [registration]);
}
/** The grant key's client identity: the host's configured client source, never an issued DCR client_id. */
export function clientIdentity(selection: ClientSelection): string {
  return selection.source === "dcr" ? "dcr" : `${selection.source}:${selection.clientId}`;
}

export type AuthMethod = "none" | "client_secret_basic" | "client_secret_post";
export interface SourceChoice { readonly source: ClientSource; readonly clientId?: string; readonly method?: AuthMethod }

/** Loopback redirects match a declared entry without the port (RFC 8252 §7.3); others exactly. */
function declared(redirect: string, entries: readonly string[]): boolean {
  if (entries.includes(redirect)) return true;
  const loopback = loopbackRedirect(redirect);
  if (!loopback) return false;
  return entries.some(entry => {
    const other = loopbackRedirect(entry);
    return other !== undefined && other.hostname === loopback.hostname &&
      other.pathname === loopback.pathname && other.search === loopback.search;
  });
}

/**
 * A selected CIMD URL is the client_id verbatim: https, a path, no userinfo, fragment or
 * dot segments. The login redirect is checked against the document only when a login is created.
 */
function cimd(client: ClientConfig, login: boolean): SourceChoice {
  const { url } = client.clientMetadataDocument!;
  let parsed: URL;
  try { parsed = new URL(url); } catch { throw new AuthError("invalid_configuration"); }
  const path = /^https:\/\/[^/?#]*(\/[^?#]*)?/i.exec(url)?.[1] ?? "";
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || url.includes("#") || /^https:\/\/[^/?#]*@/i.test(url) ||
      path.length <= 1 || path.split("/").some(segment => /^(?:\.|%2e){1,2}$/i.test(segment))) {
    throw new AuthError("invalid_configuration");
  }
  if (login) cimdRedirect(client);
  return { source: "cimd", clientId: url, method: "none" };
}
/** Before a CIMD login: its redirect must match one of the document's `redirect_uris`. */
export function cimdRedirect(client: ClientConfig): void {
  if (!client.redirectUri || !declared(client.redirectUri, client.clientMetadataDocument?.redirectUris ?? [])) {
    throw new AuthError("invalid_configuration");
  }
}

/** Eligible DCR, checked in contract order without network access. */
export function dcr(client: ClientConfig, metadata: Record<string, unknown>, secrets: boolean, requireEndpoint: boolean): SourceChoice {
  const endpoint = metadata.registration_endpoint;
  if (!client.registration || (requireEndpoint && typeof endpoint !== "string")) throw new AuthError("credential_unavailable");
  let method: AuthMethod = "none";
  if (client.flow === "client_credentials") {
    const raw = metadata.token_endpoint_auth_methods_supported;
    const supported = Array.isArray(raw) ? raw : ["client_secret_basic"];
    if (!secrets) throw new AuthError("credential_unavailable");
    if (supported.includes("client_secret_basic")) method = "client_secret_basic";
    else if (supported.includes("client_secret_post")) method = "client_secret_post";
    else throw new AuthError("credential_unavailable");
  }
  if (typeof endpoint === "string") https(endpoint);
  return { source: "dcr", method };
}

/**
 * Pre-registered, then CIMD, then permitted DCR. A recorded CIMD or DCR selection
 * survives authorization-server metadata changes until host policy changes it. A PKCE
 * redirect is checked first: `localhost` or other non-loopback `http` is invalid.
 */
export function chooseSource(client: ClientConfig, metadata: Record<string, unknown>, secrets: boolean,
  recorded?: ClientSelection, login = true): SourceChoice {
  const pkce = client.flow === "authorization_code_pkce";
  if (pkce && client.redirectUri !== undefined) checkRedirect(client.redirectUri);
  if (client.clientId !== undefined) return { source: "preregistered", clientId: client.clientId };
  if (recorded?.source === "cimd" && pkce && client.clientMetadataDocument?.url === recorded.clientId) return cimd(client, login);
  if (recorded?.source === "dcr" && client.registration) return dcr(client, metadata, secrets, false);
  if (pkce && client.clientMetadataDocument && metadata.client_id_metadata_document_supported === true) return cimd(client, login);
  return dcr(client, metadata, secrets, true);
}

/** The RFC 7591 request; a PKCE request names the login's exact redirect. */
export function registrationRequest(client: ClientConfig, method: AuthMethod): Record<string, unknown> {
  const policy = client.registration!;
  const pkce = client.flow === "authorization_code_pkce";
  return {
    ...(pkce ? { redirect_uris: [client.redirectUri] } : {}),
    ...(pkce && loopbackRedirect(client.redirectUri!) ? { application_type: "native" } : {}),
    grant_types: pkce ? ["authorization_code", "refresh_token"] : ["client_credentials"],
    ...(pkce ? { response_types: ["code"] } : {}),
    token_endpoint_auth_method: method,
    client_name: policy.clientName,
    ...(policy.softwareId === undefined ? {} : { software_id: policy.softwareId }),
    ...(policy.softwareVersion === undefined ? {} : { software_version: policy.softwareVersion }),
    ...(policy.scopes === undefined ? {} : { scope: [...new Set(policy.scopes)].join(" ") }),
  };
}

export interface AcceptedRegistration {
  readonly clientId: string;
  /** Client credentials only: a PKCE (`none`) client's secret is ignored. */
  readonly clientSecret?: string;
  readonly clientSecretExpiresAt?: number;
}

/** Map a registration response in contract table order; `now` is Unix seconds. */
export function acceptRegistration(flow: ClientConfig["flow"], request: Record<string, unknown>, status: number,
  body: unknown, now: number): AcceptedRegistration {
  if (status >= 300 && status < 400) throw new AuthError("untrusted_destination");
  const json = typeof body === "object" && body !== null && !Array.isArray(body) ? body as Record<string, unknown> : undefined;
  if ((status === 200 || status === 201) && json) {
    const pkce = flow === "authorization_code_pkce";
    const requested = (request.redirect_uris ?? []) as string[];
    const list = (value: unknown) => Array.isArray(value) && value.every(item => typeof item === "string");
    const { client_id: clientId, client_secret: secret, client_secret_expires_at: expires } = json;
    const redirects = json.redirect_uris, grants = json.grant_types;
    if (typeof clientId !== "string" || !clientId ||
        // Client credentials request no redirect: any echoed list is accepted, a non-list is not.
        (redirects !== undefined && (pkce ? !list(redirects) || !requested.every(uri => (redirects as string[]).includes(uri))
          : !Array.isArray(redirects))) ||
        (grants !== undefined && (!list(grants) || !(grants as string[]).includes(pkce ? "authorization_code" : "client_credentials"))) ||
        (json.token_endpoint_auth_method !== undefined && json.token_endpoint_auth_method !== request.token_endpoint_auth_method) ||
        (!pkce && (typeof secret !== "string" || !secret ||
          (expires !== undefined && (typeof expires !== "number" || !Number.isSafeInteger(expires) || expires < 0 ||
            (expires !== 0 && expires <= now)))))) {
      throw new AuthError("invalid_configuration");
    }
    // As the MCP TypeScript SDK does, a public client's secret and its expiry are ignored.
    if (pkce) return { clientId };
    return { clientId, clientSecret: secret as string, ...(expires === undefined ? {} : { clientSecretExpiresAt: expires as number }) };
  }
  if (status >= 200 && status < 300) throw new AuthError("provider_failed");
  if (status === 401 || status === 403) throw new AuthError("credential_unavailable");
  if (status === 408 || status === 429) throw new AuthError("provider_failed");
  if (status >= 400 && status < 500) throw new AuthError("invalid_configuration");
  throw new AuthError("provider_failed");
}

/** Milliseconds from `Retry-After` (delta-seconds or HTTP-date), if present and valid. */
export function retryAfter(value: string | null, now: number): number | undefined {
  if (value === null) return undefined;
  const text = value.trim();
  if (/^[0-9]+$/.test(text)) return Number(text) * 1000;
  const date = Date.parse(text);
  return Number.isFinite(date) ? Math.max(0, date - now) : undefined;
}

/** A registration attempt that reached the network: a client, or a failure for the backoff. */
export type Attempted = { readonly accepted: AcceptedRegistration } | { readonly error: AuthError; readonly retryAfterMs?: number };

/**
 * POST one RFC 7591 request. Destination failures and caller cancellation throw before
 * it is sent; afterwards every response or transport outcome is returned.
 */
export async function register(endpoint: string, request: Record<string, unknown>, accessToken: string | undefined,
  flow: ClientConfig["flow"], options: ManagedOAuthOptions, operation: Operation): Promise<Attempted> {
  const url = https(endpoint), approved = url.href;
  active(operation);
  try {
    await options.checkDestination(url, "registration", operation);
  } catch (error) {
    active(operation);
    throw classifyAuthError(error, "untrusted_destination");
  }
  active(operation);
  if (url.href !== approved) throw new AuthError("untrusted_destination");
  const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
  if (accessToken !== undefined) headers.Authorization = `Bearer ${accessToken}`;
  let status: number, text = "", after: string | null = null;
  // Once sent, the server may have registered a client: like a token request, the
  // response is received and persisted under the commit timeout, never the caller's signal.
  const timeout = options.commitTimeoutMs ?? 30_000;
  const transfer: Operation = Object.freeze({ signal: AbortSignal.timeout(Math.min(timeout, 2_147_483_647)), deadline: Date.now() + timeout });
  try {
    // Redirects are surfaced, never followed: a 3xx is untrusted_destination.
    const response = await options.policyFetch(endpoint, { method: "POST", headers, body: JSON.stringify(request),
      redirect: "manual", signal: transfer.signal }, { purpose: "registration", operation: transfer });
    status = response.type === "opaqueredirect" || response.redirected ? 302 : response.status;
    after = response.headers.get("retry-after");
    if (status === 200 || status === 201) text = await response.text();
    else void response.body?.cancel().catch(() => {});
  } catch (error) {
    return { error: classifyAuthError(error, "provider_failed").code === "untrusted_destination"
      ? new AuthError("untrusted_destination") : new AuthError("provider_failed") };
  }
  let body: unknown;
  try { body = text ? JSON.parse(text) : undefined; } catch { body = undefined; }
  try {
    return { accepted: acceptRegistration(flow, request, status, body, Math.floor(Date.now() / 1000)) };
  } catch (error) {
    const retry = retryAfter(after, Date.now());
    return { error: error as AuthError, ...(retry === undefined ? {} : { retryAfterMs: retry }) };
  }
}
