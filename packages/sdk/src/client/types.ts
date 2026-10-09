import type {
  EventInputs,
  EventType,
  Permission,
  ContentSourceBinding,
  DeliveryDiagnosticCode,
} from "../draft/generated.js";
import type { AttachmentContent, ContentSource } from "./content.js";
import type {
  Capabilities,
  ContentReference,
  ExecutionEventContextCompactBefore,
  InterceptResponse,
  InterceptRequest,
  Event,
  StaticCapabilityManifest,
} from "../draft/generated.js";
import type { AuthProvider, DeliveryAuthProvider } from "./auth.js";

export type { Event } from "../draft/generated.js";
export type { EventType } from "../draft/generated.js";
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
  ? ContentReference | ContentSource | ReadableStream<Uint8Array>
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
/** Generated, flattened host facts for named boundary calls. */
export type EventInput<K extends EventType> = HarnessValue<EventInputs[K]>;
/** Explicit delivery authority for one event. Effects remain separately granted. */
export interface EventGrant {
  modes: ("intercept" | "observe")[];
  capabilities?: Capabilities;
}
/** A plain capability value grants interception only. Omitted events grant nothing. */
export type EventCapabilities = Partial<
  Record<EventType, Capabilities | EventGrant>
>;
export interface HooksOptions {
  source: string;
  /** A static manifest, or explicit event declarations. Plain Capabilities
   * entries grant intercept only; use EventGrant to opt into observe. Omitted
   * events, delivery modes, effects and elicitation form/url grants stay absent. */
  capabilities: StaticCapabilityManifest | EventCapabilities;
  auth?: AuthProvider | DeliveryAuthProvider;
  /** Trusted HTTP network adapter (for example, host-managed TLS). The SDK still
   * owns protocol/authentication and cancellation. Scope transport credentials
   * to their exact destination; upload requests must not inherit event TLS identity.
   * OAuth discovery/token requests use the separate auth({ fetch }) override. */
  fetch?: typeof globalThis.fetch;
  /** Bound the immutable raw-content snapshot held by each boundary. */
  maxContentBytes?: number;
  /** Best-effort observation budget, bounded by the operation signal. */
  observationTimeoutMs?: number;
}
export interface BoundaryOptions {
  /** Generated named slots bind owned sources to producer descriptors, without refs. */
  contentSources?: readonly ContentSourceBinding<
    ContentSource | ReadableStream<Uint8Array>
  >[];
  /** Canonical pending state before any interceptor runs. */
  initialState?: InterceptRequest["params"]["state"];
  /** One operation budget: queue, authentication, content, delivery and observations. */
  signal?: AbortSignal;
  /** Complete narrowed advertisement; omitted controls stay absent. */
  capabilities?: Capabilities;
}
/** Structured SDK delivery evidence; messages and credential material are excluded. */
export interface DeliveryDiagnostic extends Omit<DeliveryError, "code"> {
  code: DeliveryDiagnosticCode;
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
/** Immutable JSON snapshot, including nested candidate values and extensions. */
// Bound recursive JSON extension types for TypeScript; runtime freezing has no
// depth limit. Six levels cover the canonical containers and nested JSON data.
type StateDepth = [0, 0, 1, 2, 3, 4, 5];
type ReadonlyState<T, D extends number = 6> = T extends
  | string
  | number
  | boolean
  | null
  | undefined
  ? T
  : D extends 0
    ? Readonly<T>
    : T extends object
      ? { readonly [P in keyof T]: ReadonlyState<T[P], StateDepth[D]> }
      : T;
/** Canonical pending state after the last accepted settlement. */
export type BoundaryState = ReadonlyState<
  NonNullable<InterceptRequest["params"]["state"]>
>;
export interface BoundaryResult<K extends EventType = EventType> {
  /** Present for owned Attachments. Effective local bodies by content item id,
   * including unread lazy sources. Close explicitly, independently of Hooks. */
  readonly content?: AttachmentContent;
  /** Accepted effective input, with occurrence identity and static envelope supplied.
   * Body streams are owned delivery resources, not reusable output streams. */
  event: HarnessEvent<K>;
  /** Effective canonical effects. The harness enacts them; the SDK executes no operation. */
  response: InterceptResponse;
  /** Detached, deeply frozen canonical state; no effects replay is needed.
   * An interrupted boundary must not execute, even if earlier accepted state
   * contains a candidate or permission. With no acceptance, initialState is
   * preserved (or the neutral candidate/permission state is returned). */
  readonly state: BoundaryState;
  /** Canonical settled permission. None is not approval; interruption forbids execution. */
  readonly permission: `${Permission}`;
  /** Accepted tool arguments, not the original proposal. Validate in host code before use. */
  readonly input: unknown;
  /** All interception and observation delivery diagnostics. */
  diagnostics: DeliveryDiagnostic[];
  errors: DeliveryError[];
  /** Compatibility view of observation diagnostics; already settled when the call returns. */
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
