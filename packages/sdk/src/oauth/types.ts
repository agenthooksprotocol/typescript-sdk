import type { AuthorizationServer } from "oauth4webapi";
import type { DeliveryAuthContext } from "../client/auth.js";

export interface Operation { readonly signal: AbortSignal; readonly deadline: number }
export type NetworkPurpose = "metadata" | "token" | "authorization" | "registration";
/** Must enforce DNS/connect policy and reject redirects; no global fetch fallback exists. */
export type PolicyFetch = (url: string, init: RequestInit, context: {
  readonly purpose: NetworkPurpose; readonly operation: Operation;
}) => Promise<Response>;
/** How a grant's `client_id` was obtained, in selection order. */
export type ClientSource = "preregistered" | "cimd" | "dcr";
/** A Client ID Metadata Document the host publishes; the SDK never fetches it. */
export interface ClientMetadataDocument {
  /** HTTPS URL with a path; sent verbatim as the `client_id`. */
  readonly url: string;
  /** The document's `redirect_uris`; the login redirect must equal one exactly. */
  readonly redirectUris: readonly string[];
}
/** Host permission to register a client (RFC 7591) at this config's exact issuer. */
export interface RegistrationPolicy {
  readonly clientName: string;
  readonly softwareId?: string;
  readonly softwareVersion?: string;
  /** Sent as `scope` only when supplied; never derived from an operation. */
  readonly scopes?: readonly string[];
  /** Initial access token, resolved through `secrets.get` and sent only to this issuer. */
  readonly initialAccessTokenRef?: string;
}
export interface ClientConfig {
  readonly issuer: string; readonly resource: string;
  /** Pre-registered client. It always wins; without it the SDK tries CIMD, then DCR. */
  readonly clientId?: string;
  readonly flow: "authorization_code_pkce" | "client_credentials";
  readonly scopes: readonly string[];
  /** Local ceiling; defaults to `scopes`. Not part of the grant key. */
  readonly allowedScopes?: readonly string[];
  readonly requiredScopes?: readonly string[];
  readonly grantPartition?: string;
  readonly clientSecret?: string; readonly redirectUri?: string;
  /** PKCE only, used when the issuer advertises `client_id_metadata_document_supported: true`. */
  readonly clientMetadataDocument?: ClientMetadataDocument;
  /** Permits dynamic registration at `issuer` when it advertises `registration_endpoint`. */
  readonly registration?: RegistrationPolicy;
}
/** Selected client identity recorded on a binding. */
export interface ClientSelection {
  readonly source: ClientSource;
  readonly clientId: string;
  /** DCR only. */
  readonly registrationKey?: string;
  /** DCR only: the registration policy digest the selection was made under. */
  readonly requestDigest?: string;
}
export interface ResolvedTarget {
  readonly client: ClientConfig;
  readonly metadata: AuthorizationServer;
  /** Current host policy only; never inferred from a challenge. */
  readonly hostRequiredScopes?: readonly string[];
}
export interface TokenValue {
  readonly token: string; readonly expiresAt?: number;
  readonly refreshToken?: string; readonly scopes: readonly string[];
}

/** One OAuth grant. `token` is absent after a rejection or an invalid token response. */
export interface StoredGrant {
  readonly kind: "grant";
  readonly generation: string;
  readonly token?: string;
  readonly expiresAt?: number;
  readonly refreshToken?: string;
  /** Recorded granted scopes; re-intersected with the current ceiling at use. */
  readonly scopes: readonly string[];
}
/** Non-secret discovery result for one destination, stored under its binding key. */
export interface StoredBinding {
  readonly kind: "binding";
  readonly generation: string;
  readonly issuer: string;
  readonly resource: string;
  /** Persisted for refresh/acquisition. If absent, the lookup fetches only the stored issuer's metadata. */
  readonly metadata?: AuthorizationServer;
  /** Unix milliseconds. Host prepare and challenge handling rebuild the binding. */
  readonly discoveredAt: number;
  /** Grant the binding was approved for; a different selection is not a lookup miss. */
  readonly grantKey?: string;
  /** Client source; kept while only authorization-server metadata changes. */
  readonly client?: ClientSelection;
}
/** A dynamically registered client, shared by every grant with its registration key. */
export interface StoredRegistration {
  readonly kind: "registration";
  readonly generation: string;
  readonly clientId: string;
  /** Unix seconds; absent or 0 means no known expiry. */
  readonly clientSecretExpiresAt?: number;
  /** Local Unix milliseconds when stored. */
  readonly registeredAt: number;
  /** Accepted, non-secret issued metadata. */
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly requestDigest: string;
  /** Confidential clients only: opaque `secrets` reference, never the secret. */
  readonly secretRef?: string;
}
/** Backoff after a failed registration, under `frame("ahp.oauth.registration-failure:", [registrationKey])`. */
export interface StoredRegistrationFailure {
  readonly kind: "registration_failure";
  readonly generation: string;
  readonly requestDigest: string;
  /** Unix milliseconds. */
  readonly failedAt: number;
  readonly attempts: number;
  /** Unix milliseconds before which only host `prepare` registers. */
  readonly nextAttemptAt: number;
}
/** A host-created login awaiting its callback. Completable from any process sharing the store. */
export interface StoredPendingLogin {
  readonly kind: "pending_login";
  readonly generation: string;
  readonly id: string;
  readonly grantKey: string;
  readonly expiresAt: number;
  readonly authorizationUrl: string;
  readonly state: string;
  readonly verifier: string;
  /** Requested plus required scopes and the creating caller's ceiling, without client secrets. */
  readonly client: Omit<ClientConfig, "clientSecret">;
  readonly metadata: AuthorizationServer;
  readonly context: Pick<DeliveryAuthContext, "backendId" | "purpose" | "url" | "authentication">;
  readonly source?: ClientSource;
  /** DCR only: the registration generation the login was created under. */
  readonly registration?: { readonly key: string; readonly generation: string };
}
export type StoredRecord = StoredGrant | StoredBinding | StoredPendingLogin | StoredRegistration | StoredRegistrationFailure;
/** Host secret storage for registered client secrets. There is no default or fallback. */
export interface SecretStore {
  put(reference: string, secret: string, signal: AbortSignal): Promise<void>;
  get(reference: string, signal: AbortSignal): Promise<string | undefined>;
  delete(reference: string, signal: AbortSignal): Promise<void>;
}

/** Host implements cross-instance coordination and atomic generation checks.
 * coordinate must serialize work for a key across all instances sharing this store,
 * hold the lock until work settles, and never start an aborted waiter. Store writes
 * must check signal before committing. Every write uses a fresh generation.
 */
export interface TokenStore {
  load(key: string, signal: AbortSignal): Promise<StoredRecord | undefined>;
  compareAndSet(key: string, expectedGeneration: string | undefined,
    value: StoredRecord | undefined, signal: AbortSignal): Promise<boolean>;
  coordinate<T>(key: string, signal: AbortSignal, work: () => Promise<T>): Promise<T>;
}
export interface ManagedOAuthOptions {
  readonly namespace: string;
  readonly store: TokenStore;
  readonly policyFetch: PolicyFetch;
  /** Called for every advertised endpoint, including the authorization URL. */
  readonly checkDestination: (url: URL, purpose: NetworkPurpose, operation: Operation) => void | Promise<void>;
  /** Local trust/identity/scope policy, never inferred from advertised metadata. */
  readonly selectClient: (issuers: readonly string[], resource: string,
    context: DeliveryAuthContext, operation: Operation) => ClientConfig | Promise<ClientConfig>;
  /** Budget for persisting a received token response, independent of the caller. Default 30000. */
  readonly commitTimeoutMs?: number;
  /** Pending login lifetime, fixed at creation. Default and maximum 600000 (10 minutes). */
  readonly loginLifetimeMs?: number;
  /** Required for client-credentials DCR; resolves initial access token references. */
  readonly secrets?: SecretStore;
  /** Failed-registration backoff: `initialMs` (default 60000) doubling per attempt, capped
   * with any `Retry-After` at `maxMs` (default 3600000). */
  readonly registrationBackoff?: { readonly initialMs?: number; readonly maxMs?: number };
  /** Cap on the proactive client-secret renewal margin, `min(0.1 × lifetime, cap)`. Default 3600000. */
  readonly renewalMarginMs?: number;
}
