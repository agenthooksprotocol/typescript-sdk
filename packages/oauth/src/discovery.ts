import { AuthError, type DeliveryAuthContext } from "agenthooksprotocol/client/auth";
import { processDiscoveryResponse, type AuthorizationServer } from "oauth4webapi";
import type { ClientConfig, ManagedOAuthOptions, NetworkPurpose, Operation, ResolvedTarget } from "./types.js";

function active(operation: Operation): void {
  if (operation.signal.aborted || Date.now() >= operation.deadline) {
    throw new AuthError("provider_failed");
  }
}

function https(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new AuthError("untrusted_destination"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || value.includes("#")) {
    throw new AuthError("untrusted_destination");
  }
  return url;
}

/** The host must enforce DNS/connect policy, not merely inspect this URL. */
export async function checkedFetch(
  url: string,
  init: RequestInit,
  purpose: NetworkPurpose,
  options: ManagedOAuthOptions,
  operation: Operation,
): Promise<Response> {
  const destination = https(url);
  const original = destination.href;
  active(operation);
  try {
    await options.checkDestination(destination, purpose, operation);
  } catch { throw new AuthError("untrusted_destination"); }
  active(operation);
  if (destination.href !== original) throw new AuthError("untrusted_destination");
  let response: Response;
  try {
    response = await options.policyFetch(url, { ...init, redirect: "error", signal: operation.signal }, { purpose, operation });
  } catch { throw new AuthError("provider_failed"); }
  active(operation);
  if (response.redirected || (response.url !== "" && response.url !== url)) {
    throw new AuthError("untrusted_destination");
  }
  return response;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new AuthError("discovery_failed");
  return value as Record<string, unknown>;
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value) || value.some(item => typeof item !== "string" || item.length === 0)) {
    throw new AuthError("discovery_failed");
  }
  return value as string[];
}

async function metadataAt(urls: readonly string[], options: ManagedOAuthOptions, operation: Operation, expectedResources?: ReadonlyMap<string, string>, expectedIssuer?: string): Promise<Record<string, unknown>> {
  for (const url of new Set(urls)) {
    const response = await checkedFetch(url, { headers: { Accept: "application/json" } }, "metadata", options, operation);
    // A malformed or rejected document must never cause a downgrade to another location.
    if (response.status === 404) continue;
    if (!response.ok) throw new AuthError("discovery_failed");
    try {
      const body: unknown = expectedIssuer === undefined
        ? await response.json()
        : await processDiscoveryResponse(new URL(expectedIssuer), response);
      active(operation);
      const metadata = record(body);
      // Signed metadata needs a host verifier; never use unverified JWT claims.
      if (metadata.signed_metadata !== undefined) throw new AuthError("unsupported_binding");
      if (expectedResources && metadata.resource !== expectedResources.get(url)) throw new AuthError("discovery_failed");
      return metadata;
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError("discovery_failed");
    }
  }
  throw new AuthError("discovery_failed");
}

/** Split challenges without interpreting commas or scheme names inside quoted strings. */
function bearerParameters(header: string | undefined): Map<string, string> {
  const result = new Map<string, string>();
  if (header === undefined || header === "") return result;
  if (header.length > 16384 || /[\r\n\0]/.test(header)) throw new AuthError("discovery_failed");
  const parts: string[] = [];
  let start = 0, quoted = false, escaped = false;
  for (let i = 0; i < header.length; i++) {
    const c = header[i];
    if (escaped) { escaped = false; continue; }
    if (quoted && c === "\\") { escaped = true; continue; }
    if (c === '"') quoted = !quoted;
    if (c === "," && !quoted) { parts.push(header.slice(start, i)); start = i + 1; }
  }
  if (quoted || escaped) throw new AuthError("discovery_failed");
  parts.push(header.slice(start));
  let bearer = false, seenBearer = false;
  const token = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
  const scheme = new RegExp(`^(${token})(?:[ \\t]+(.*))?$`);
  const parameter = new RegExp(`^(${token})[ \\t]*=[ \\t]*(?:\"((?:[^\"\\\\]|\\\\.)*)\"|(${token}))[ \\t]*$`);
  for (const part of parts) {
    let text = part.trim();
    const beginning = scheme.exec(text);
    if (beginning && !parameter.test(text)) {
      bearer = beginning[1]?.toLowerCase() === "bearer";
      if (bearer && seenBearer) throw new AuthError("discovery_failed");
      if (bearer) seenBearer = true;
      text = beginning[2] ?? "";
    }
    if (!bearer || text === "") continue;
    const match = parameter.exec(text);
    if (!match) throw new AuthError("discovery_failed");
    const name = match[1]!.toLowerCase();
    if (result.has(name)) throw new AuthError("discovery_failed");
    result.set(name, match[2] !== undefined ? match[2].replace(/\\(.)/g, "$1") : match[3]!);
  }
  return result;
}

function resourceCovers(resource: string, endpoint: string): void {
  const base = https(resource), target = https(endpoint);
  if (base.search || resource.includes("?") || base.origin !== target.origin ||
      !(target.pathname === base.pathname || target.pathname.startsWith(base.pathname.replace(/\/$/, "") + "/"))) {
    throw new AuthError("discovery_failed");
  }
}

function validateClient(client: ClientConfig): void {
  if (!client || typeof client.issuer !== "string" || typeof client.resource !== "string" ||
      typeof client.clientId !== "string" || !client.clientId.trim() ||
      !["authorization_code_pkce", "client_credentials"].includes(client.flow)) throw new AuthError("invalid_configuration");
  const issuer = https(client.issuer);
  https(client.resource);
  if (issuer.search || client.issuer.includes("?")) throw new AuthError("invalid_configuration");
  if (!Array.isArray(client.scopes) || client.scopes.some(scope => typeof scope !== "string" || !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) {
    throw new AuthError("invalid_configuration");
  }
}

export async function resolveTarget(context: DeliveryAuthContext, options: ManagedOAuthOptions, operation: Operation): Promise<ResolvedTarget> {
  try {
    return await discover(context, options, operation);
  } catch (error) {
    if (error instanceof AuthError) throw error;
    throw new AuthError("discovery_failed");
  }
}

async function discover(context: DeliveryAuthContext, options: ManagedOAuthOptions, operation: Operation): Promise<ResolvedTarget> {
  active(operation);
  const binding = context.authentication;
  if (binding !== undefined && binding.type !== "oauth") throw new AuthError("unsupported_binding");
  if (!binding && context.challenged !== true) throw new AuthError("credential_unavailable");
  const endpoint = https(context.url);
  const challenge = bearerParameters(context.challenge);
  const advertised = challenge.get("resource_metadata");
  if (advertised !== undefined && advertised === "") throw new AuthError("discovery_failed");
  const path = endpoint.pathname === "/" ? "" : endpoint.pathname;
  const specific = `${endpoint.origin}/.well-known/oauth-protected-resource${path}`;
  const root = `${endpoint.origin}/.well-known/oauth-protected-resource`;
  // RFC 9728 section 3.3 binds the returned identifier to the discovery source.
  const expected = advertised !== undefined
    ? new Map([[advertised, context.url]])
    : new Map([[specific, `${endpoint.origin}${path}`], [root, endpoint.origin]]);
  const protectedResource = await metadataAt(advertised !== undefined ? [advertised] : [specific, root], options, operation, expected);
  if (typeof protectedResource.resource !== "string") throw new AuthError("discovery_failed");
  const resource = protectedResource.resource;
  resourceCovers(resource, context.url);
  const issuers = strings(protectedResource.authorization_servers);
  if (issuers.length === 0) throw new AuthError("discovery_failed");
  for (const value of issuers) {
    const issuer = https(value);
    if (issuer.search || value.includes("?")) throw new AuthError("discovery_failed");
  }
  if (protectedResource.bearer_methods_supported !== undefined &&
      !strings(protectedResource.bearer_methods_supported).includes("header")) throw new AuthError("discovery_failed");
  if (binding && (binding.resource !== resource || !issuers.includes(binding.issuer))) throw new AuthError("invalid_configuration");
  let selected: ClientConfig;
  try {
    selected = await options.selectClient(Object.freeze(binding ? [binding.issuer] : [...issuers]), resource, context, operation);
  } catch { throw new AuthError("credential_unavailable"); }
  active(operation);
  validateClient(selected);
  if ((selected.flow === "client_credentials" || binding?.clientSecretRef !== undefined) &&
      (typeof selected.clientSecret !== "string" || !selected.clientSecret)) throw new AuthError("credential_unavailable");
  if (!issuers.includes(selected.issuer) || selected.resource !== resource) throw new AuthError("invalid_configuration");
  if (binding && (selected.issuer !== binding.issuer || selected.resource !== binding.resource ||
      selected.clientId !== binding.clientId || selected.flow !== binding.flow ||
      JSON.stringify([...selected.scopes].sort()) !== JSON.stringify([...(binding.scopes ?? [])].sort()))) throw new AuthError("invalid_configuration");
  // Snapshot host-owned configuration before subsequent asynchronous policy calls.
  const client: ClientConfig = Object.freeze({ ...selected, scopes: Object.freeze([...selected.scopes]) });
  const required = challenge.get("scope");
  if (required !== undefined) {
    if (!/^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/.test(required) ||
        required.split(" ").some(scope => !client.scopes.includes(scope))) throw new AuthError("access_denied");
  }
  const issuer = https(client.issuer);
  const issuerPath = issuer.pathname === "/" ? "" : issuer.pathname;
  const metadata = await metadataAt([
    `${issuer.origin}/.well-known/oauth-authorization-server${issuerPath}`,
    `${issuer.origin}/.well-known/openid-configuration${issuerPath}`,
    `${issuer.origin}${issuerPath.replace(/\/$/, "")}/.well-known/openid-configuration`,
  ], options, operation, undefined, client.issuer);
  if (metadata.issuer !== client.issuer || typeof metadata.token_endpoint !== "string") throw new AuthError("discovery_failed");
  if (metadata.protected_resources !== undefined &&
      !strings(metadata.protected_resources).includes(client.resource)) throw new AuthError("discovery_failed");
  https(metadata.token_endpoint);
  if (metadata.authorization_endpoint !== undefined) {
    if (typeof metadata.authorization_endpoint !== "string") throw new AuthError("discovery_failed");
    https(metadata.authorization_endpoint);
  }
  if (client.flow === "client_credentials" &&
      (metadata.grant_types_supported === undefined || !strings(metadata.grant_types_supported).includes("client_credentials"))) {
    throw new AuthError("unsupported_binding");
  }
  if (client.flow === "authorization_code_pkce") {
    if (typeof metadata.authorization_endpoint !== "string" ||
        metadata.code_challenge_methods_supported === undefined ||
        !strings(metadata.code_challenge_methods_supported).includes("S256") ||
        (metadata.grant_types_supported !== undefined && !strings(metadata.grant_types_supported).includes("authorization_code"))) {
      throw new AuthError("unsupported_binding");
    }
  }
  return { client, metadata: metadata as unknown as AuthorizationServer };
}
