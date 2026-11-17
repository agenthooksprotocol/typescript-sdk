import type { AuthorizationServer } from "oauth4webapi";
import type { DeliveryAuthContext } from "../client/auth.js";

export interface Operation { readonly signal: AbortSignal; readonly deadline: number }
export type NetworkPurpose = "metadata" | "token" | "authorization";
/** Must enforce DNS/connect policy and reject redirects; no global fetch fallback exists. */
export type PolicyFetch = (url: string, init: RequestInit, context: {
  readonly purpose: NetworkPurpose; readonly operation: Operation;
}) => Promise<Response>;
export interface ClientConfig {
  readonly issuer: string; readonly resource: string; readonly clientId: string;
  readonly flow: "authorization_code_pkce" | "client_credentials";
  readonly scopes: readonly string[];
  /** Local ceiling; defaults to `scopes`. Not part of the grant key. */
  readonly allowedScopes?: readonly string[];
  readonly requiredScopes?: readonly string[];
  readonly grantPartition?: string;
  readonly clientSecret?: string; readonly redirectUri?: string;
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
  readonly metadata: AuthorizationServer;
  /** Unix milliseconds; metadata older than `metadataMaxAgeMs` is renewed before acquisition. */
  readonly discoveredAt: number;
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
}
export type StoredRecord = StoredGrant | StoredBinding | StoredPendingLogin;

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
  /** Pending login lifetime, fixed at creation. Default and maximum 600000 (10 minutes). */
  readonly loginLifetimeMs?: number;
  /** Cached authorization-server metadata age before renewal for acquisition. Default 3600000. */
  readonly metadataMaxAgeMs?: number;
}
