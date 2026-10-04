import type {
  Capabilities,
  ContentReference,
  ExecutionEventContextCompactBefore,
  InterceptResponse,
  InterceptRequest,
  ObserveNotification,
  StaticCapabilityManifest,
} from "../draft/generated.js";
import type { AuthProvider } from "./auth.js";

export type Event = ObserveNotification["params"]["event"];
export type EventType = Event["type"];
/** Remove generated JSON extension index signatures while preserving named fields. */
type Fields<T> = {
  [K in keyof T as string extends K
    ? never
    : number extends K
      ? never
      : K]: T[K];
};
/** Harness content bodies may be owned streams instead of uploaded references. */
export type HarnessValue<T> = T extends ContentReference
  ? ContentReference | ReadableStream<Uint8Array>
  : T extends readonly (infer V)[]
    ? HarnessValue<V>[]
    : T extends { selection: string }
      ? Omit<
          { [K in keyof Fields<T>]: HarnessValue<Fields<T>[K]> },
          "selection"
        > & { selection?: T["selection"] }
      : T extends object
        ? keyof Fields<T> extends never
          ? T
          : { [K in keyof Fields<T>]: HarnessValue<Fields<T>[K]> }
        : T;
// The generated compact-before JsonValue intersection includes impossible
// primitive/array event branches. Remove those branches before mapping content
// bodies; otherwise Omit sees their shared keys and loses canonical fields.
type CompactBeforeObject = Exclude<
  ExecutionEventContextCompactBefore,
  string | number | boolean | readonly unknown[]
>;
export type HarnessEvent<K extends EventType = EventType> =
  K extends "context.compact.before"
    ? Omit<HarnessValue<CompactBeforeObject>, "trigger"> &
        Pick<CompactBeforeObject, "trigger">
    : HarnessValue<Extract<Event, { type: K }>>;
/** Passing a body stream transfers its read/cancel ownership to the SDK.
 * Keep host execution data separately; canonical effects carry accepted rewrites. */
export type BoundaryInput<K extends EventType> = K extends EventType
  ? Omit<HarnessEvent<K>, "type" | "source" | "id" | "time" | "manifest"> & {
      id?: string;
      time?: string;
    }
  : never;
export type EventCapabilities = Partial<Record<EventType, Capabilities>>;
export interface HooksOptions {
  source: string;
  /** A static manifest, or an event-to-capabilities map of interceptable events. */
  capabilities: StaticCapabilityManifest | EventCapabilities;
  auth?: AuthProvider;
  /** Trusted HTTP network adapter (for example, host-managed TLS). The SDK still
   * owns protocol/authentication and cancellation. Scope transport credentials
   * to their exact destination; upload requests must not inherit event TLS identity.
   * OAuth discovery/token requests use the separate auth({ fetch }) override. */
  fetch?: typeof globalThis.fetch;
  /** Bound the immutable raw-content snapshot held by each boundary. */
  maxContentBytes?: number;
  /** Best-effort observation budget; observation never delays the boundary result. */
  observationTimeoutMs?: number;
}
export interface BoundaryOptions {
  /** Canonical pending state before any interceptor runs. */
  state?: InterceptRequest["params"]["state"];
  signal?: AbortSignal;
  /** Complete narrowed advertisement; omitted controls stay absent. */
  capabilities?: Capabilities;
}
export interface DeliveryError {
  backendId: string;
  subscriptionIndex: number;
  phase: "preparation" | "interception" | "observation";
  code:
    | "PREPARATION_FAILED"
    | "DELIVERY_FAILED"
    | "DEADLINE_EXCEEDED"
    | "INTERRUPTED";
  failurePolicy?: "fail-open" | "fail-closed";
  syntheticDenial: boolean;
}
export interface BoundaryResult<K extends EventType = EventType> {
  /** Accepted effective input, with occurrence identity and static envelope supplied.
   * Body streams are owned delivery resources, not reusable output streams. */
  event: HarnessEvent<K>;
  /** Effective canonical effects. The harness enacts them; the SDK executes no operation. */
  response: InterceptResponse;
  errors: DeliveryError[];
  /** Optional explicit wait for best-effort deliveries; never delays interception. */
  observations: Promise<DeliveryError[]>;
  interrupted: boolean;
}
export interface ConfigurationIssue {
  path: string;
  code: string;
}
export class ConfigurationError extends Error {
  readonly code = "INVALID_CONFIGURATION";
  constructor(readonly issues: readonly ConfigurationIssue[]) {
    super("Hook configuration could not be resolved");
    this.name = "ConfigurationError";
  }
}
