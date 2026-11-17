import { AuthError, classifyAuthError } from "../client/auth.js";
import { active, https } from "./discovery.js";
import type { ClientConfig, ClientSelection, ClientSource, ManagedOAuthOptions, Operation, RegistrationPolicy } from "./types.js";

/** Canonical UTF-8 framed SDK storage identity. */
export function frame(prefix: string, fields: readonly string[]): string {
  const encoder = new TextEncoder();
  return prefix + fields.map(value => `${encoder.encode(value).length}:${value}`).join("");
}
/** Shared by every grant with the same namespace, exact issuer, flow and redirect. */
export function registrationKey(namespace: string, issuer: string, flow: ClientConfig["flow"], redirect: string): string {
  return frame("ahp.oauth.registration:", [namespace, issuer, flow, flow === "client_credentials" ? "" : redirect]);
}
export function failureKey(registration: string): string {
  return frame("ahp.oauth.registration-failure:", [registration]);
}
/** Digest of host registration policy; a record registered under another digest is unusable. */
export async function requestDigest(policy: RegistrationPolicy): Promise<string> {
  const scope = [...new Set(policy.scopes ?? [])].sort().join(" ");
  const framed = frame("ahp.oauth.registration-request:", [policy.clientName, policy.softwareId ?? "",
    policy.softwareVersion ?? "", scope, policy.initialAccessTokenRef ?? ""]);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(framed));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

export type AuthMethod = "none" | "client_secret_basic" | "client_secret_post";
export interface SourceChoice { readonly source: ClientSource; readonly clientId?: string; readonly method?: AuthMethod }

/** A selected CIMD URL is the client_id verbatim: https, a path, no userinfo, fragment or dot segments. */
function cimd(client: ClientConfig): SourceChoice {
  const { url, redirectUris } = client.clientMetadataDocument!;
  let parsed: URL;
  try { parsed = new URL(url); } catch { throw new AuthError("invalid_configuration"); }
  const path = /^https:\/\/[^/?#]*(\/[^?#]*)?/i.exec(url)?.[1] ?? "";
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || url.includes("#") || /^https:\/\/[^/?#]*@/i.test(url) ||
      path.length <= 1 || path.split("/").some(segment => /^(?:\.|%2e){1,2}$/i.test(segment)) ||
      !client.redirectUri || !redirectUris.includes(client.redirectUri)) {
    throw new AuthError("invalid_configuration");
  }
  return { source: "cimd", clientId: url, method: "none" };
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
 * survives authorization-server metadata changes until host policy changes it.
 */
export function chooseSource(client: ClientConfig, metadata: Record<string, unknown>, secrets: boolean,
  recorded?: ClientSelection, digest?: string): SourceChoice {
  if (client.clientId !== undefined) return { source: "preregistered", clientId: client.clientId };
  const pkce = client.flow === "authorization_code_pkce";
  if (recorded?.source === "cimd" && pkce && client.clientMetadataDocument?.url === recorded.clientId) return cimd(client);
  if (recorded?.source === "dcr" && client.registration && digest !== undefined && recorded.requestDigest === digest) {
    return dcr(client, metadata, secrets, false);
  }
  if (pkce && client.clientMetadataDocument && metadata.client_id_metadata_document_supported === true) return cimd(client);
  return dcr(client, metadata, secrets, true);
}

export function registrationRequest(client: ClientConfig, method: AuthMethod): Record<string, unknown> {
  const policy = client.registration!;
  const pkce = client.flow === "authorization_code_pkce";
  return {
    ...(pkce ? { redirect_uris: [client.redirectUri] } : {}),
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
  readonly clientSecret?: string;
  readonly clientSecretExpiresAt?: number;
  readonly metadata: Record<string, unknown>;
}
const ISSUED = ["client_id_issued_at", "redirect_uris", "grant_types", "response_types", "token_endpoint_auth_method",
  "client_name", "software_id", "software_version"];

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
        (redirects !== undefined && (!list(redirects) || new Set(redirects as string[]).size !== new Set(requested).size ||
          !(redirects as string[]).every(uri => requested.includes(uri)))) ||
        (grants !== undefined && (!list(grants) || !(grants as string[]).includes(pkce ? "authorization_code" : "client_credentials"))) ||
        (json.token_endpoint_auth_method !== undefined && json.token_endpoint_auth_method !== request.token_endpoint_auth_method) ||
        (pkce ? secret !== undefined : typeof secret !== "string" || !secret) ||
        (expires !== undefined && (typeof expires !== "number" || !Number.isSafeInteger(expires) || expires < 0 ||
          (expires !== 0 && expires <= now)))) {
      throw new AuthError("invalid_configuration");
    }
    const metadata = Object.fromEntries(ISSUED.filter(name => json[name] !== undefined).map(name => [name, structuredClone(json[name])]));
    return { clientId, metadata, ...(pkce ? {} : { clientSecret: secret as string }),
      ...(expires === undefined ? {} : { clientSecretExpiresAt: expires as number }) };
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

/** A registration attempt that reached the network: a record, or a failure for the backoff marker. */
export type Attempted = { readonly accepted: AcceptedRegistration } | { readonly error: AuthError; readonly retryAfterMs?: number };

/**
 * POST one RFC 7591 request. Destination failures throw before any request; the
 * caller's cancellation rethrows; every response or transport outcome is returned.
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
  try {
    // Redirects are surfaced, never followed: a 3xx is untrusted_destination.
    const response = await options.policyFetch(endpoint, { method: "POST", headers, body: JSON.stringify(request),
      redirect: "manual", signal: operation.signal }, { purpose: "registration", operation });
    active(operation);
    status = response.type === "opaqueredirect" || response.redirected ? 302 : response.status;
    after = response.headers.get("retry-after");
    if (status === 200 || status === 201) text = await response.text();
    else void response.body?.cancel().catch(() => {});
  } catch (error) {
    active(operation);
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
