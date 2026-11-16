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
  readonly allowedScopes?: readonly string[];
  readonly requiredScopes?: readonly string[];
  readonly grantPartition?: string;
  readonly clientSecret?: string; readonly redirectUri?: string;
}
export interface ResolvedTarget {
  readonly client: ClientConfig;
  readonly metadata: AuthorizationServer;
  /** Current host policy only; never inferred from a challenge or cached requirements. */
  readonly hostRequiredScopes?: readonly string[];
}
export interface TokenValue {
  readonly token: string; readonly expiresAt?: number | undefined;
  readonly refreshToken?: string; readonly scopes: readonly string[];
  readonly requiredScopes?: readonly string[];
  readonly rejected?: boolean;
}
export interface StoredCredential extends TokenValue {
  readonly generation: string;
  readonly rejected?: boolean;
  readonly refreshRejected?: boolean;
  /** A rotated credential is retained, but requires explicit host consent/repair. */
  readonly refreshQuarantined?: boolean;
  /** Internal non-secret discovery cache, stored under the separate binding key. */
  readonly bindingMetadata?: ResolvedTarget;
  readonly requiredScopes?: readonly string[];
}
/** Host implements cross-instance coordination and atomic generation checks.
 * coordinate must serialize work for a key across all instances sharing this store,
 * hold the lock until work settles, and never start an aborted waiter. Store writes
 * must check signal before committing. New credentials use fresh generations;
 * rejection-only updates preserve the credential generation.
 */
export interface TokenStore {
  load(key: string, signal: AbortSignal): Promise<StoredCredential | undefined>;
  compareAndSet(key: string, expectedGeneration: string | undefined,
    value: StoredCredential | undefined, signal: AbortSignal): Promise<boolean>;
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
}
