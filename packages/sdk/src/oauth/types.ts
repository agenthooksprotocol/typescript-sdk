import type { AuthorizationServer } from "oauth4webapi";
import type { DeliveryAuthContext } from "../client/auth.js";

export interface Operation { readonly signal: AbortSignal; readonly deadline: number }
export type NetworkPurpose = "metadata" | "token" | "authorization" | "registration";
/** Must enforce DNS/connect policy and reject redirects; no global fetch fallback exists. */
export type PolicyFetch = (url: string, init: RequestInit, context: {
  readonly purpose: NetworkPurpose; readonly operation: Operation;
}) => Promise<Response>;
/** The host-configured client source, in selection order; with its client it is the grant key's client identity. */
export type ClientSource = "preregistered" | "cimd" | "dcr";
/** A Client ID Metadata Document the host publishes; the SDK never fetches it. */
export interface ClientMetadataDocument {
  /** HTTPS URL with a path; sent verbatim as the `client_id`. */
  readonly url: string;
  /** The document's `redirect_uris`; a loopback entry may omit the port, which is then not compared. */
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
  readonly clientSecret?: string;
  /** Default PKCE redirect; `prepare` may supply each login's own (for example an ephemeral loopback port). */
  readonly redirectUri?: string;
  /** PKCE only, used when the issuer advertises `client_id_metadata_document_supported: true`. */
  readonly clientMetadataDocument?: ClientMetadataDocument;
  /** Permits dynamic registration at `issuer` when it advertises `registration_endpoint`. */
  readonly registration?: RegistrationPolicy;
}
/** Selected client source recorded on a binding. */
export interface ClientSelection {
  readonly source: ClientSource;
  /** Pre-registered or CIMD only; an issued DCR client_id is never part of the selection. */
  readonly clientId?: string;
}
export interface ResolvedTarget {
  readonly client: ClientConfig;
  readonly metadata: AuthorizationServer;
  /** A registered client-credentials client's registered token endpoint auth method. */
  readonly authMethod?: "client_secret_basic" | "client_secret_post";
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
  /** PKCE with DCR: the client issued to the login that produced these tokens, used to refresh them. */
  readonly clientId?: string;
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
/** A client-credentials client registered by DCR, shared per namespace and issuer. */
export interface StoredRegistration {
  readonly kind: "registration";
  readonly generation: string;
  readonly clientId: string;
  readonly tokenEndpointAuthMethod: "client_secret_basic" | "client_secret_post";
  /** Unix seconds; absent or 0 means no known expiry. */
  readonly clientSecretExpiresAt?: number;
  /** Opaque `secrets` reference, never the secret. */
  readonly secretRef: string;
}
/** Backoff after a failed client-credentials registration, under `frame("ahp.oauth.registration-failure:", [registrationKey])`. */
export interface StoredRegistrationFailure {
  readonly kind: "registration_failure";
  readonly generation: string;
  readonly attempts: number;
  /** Unix milliseconds before which only host `prepare` registers. */
  readonly nextAttemptAt: number;
  /** The last failure's `AuthError` code, returned while the backoff lasts. */
  readonly code: string;
}
/**
 * A login awaiting its callback, found by `state`. Held by the creating process, or in
 * the store when `persistPendingLogins` is set. Only this record holds the PKCE verifier.
 */
export interface StoredPendingLogin {
  readonly kind: "pending_login";
  readonly generation: string;
  readonly state: string;
  readonly grantKey: string;
  readonly expiresAt: number;
  readonly authorizationUrl: string;
  readonly verifier: string;
  /** The login's exact redirect and client (its requested scopes, ceiling and prepare-time host-required scopes), without client secrets. */
  readonly client: Omit<ClientConfig, "clientSecret">;
  /** R the login was prepared with (H ∪ E ∪ Ch). Absent on records written by older releases. */
  readonly requiredScopes?: readonly string[];
  readonly metadata: AuthorizationServer;
  readonly context: Pick<DeliveryAuthContext, "backendId" | "purpose" | "url" | "authentication">;
  readonly source: ClientSource;
}
/** Persisted pending logins of one grant key, oldest first, for the cap. */
export interface StoredPendingIndex {
  readonly kind: "pending_index";
  readonly generation: string;
  readonly states: readonly string[];
}
export type StoredRecord = StoredGrant | StoredBinding | StoredPendingLogin | StoredPendingIndex | StoredRegistration | StoredRegistrationFailure;
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
  /**
   * Keep pending logins in `store` so any process sharing it can complete one by
   * `state` (for example a pasted callback URL). By default they live in this instance.
   */
  readonly persistPendingLogins?: boolean;
  /** Concurrent pending logins per grant key (per instance, or per store when persisted). Default 5. */
  readonly maxPendingLogins?: number;
  /** Required for client-credentials DCR; resolves initial access token references. */
  readonly secrets?: SecretStore;
  /** Client-credentials registration backoff: `initialMs` (default 60000) doubling per
   * failure, capped with any `Retry-After` at `maxMs` (default 3600000). */
  readonly registrationBackoff?: { readonly initialMs?: number; readonly maxMs?: number };
}
