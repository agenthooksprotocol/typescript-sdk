import type {
  HostEventInputs,
  HostCapabilities,
  Harness,
  OwnedAttachment,
  EventType,
  Permission,
  ContentSourceBinding,
  DeliveryDiagnosticCode,
} from "../draft/raw.js";
import type { Attachment, AttachmentContent } from "./content.js";
import type { BoundaryContracts } from "./contracts.js";
import type {
  Capabilities,
  ContentReference,
  InterceptResponse,
  EventResponses,
  ResponseFor,
  InterceptRequest,
  Event,
  StaticCapabilityManifest,
  ToolState, TextState, MessagesState, ElicitResultState,
} from "../draft/raw.js";
import type { DeliveryAuthProvider } from "./auth.js";

export type { Event } from "../draft/raw.js";
export type { EventType } from "../draft/raw.js";
/** Remove generated JSON extension index signatures while preserving named fields. */
type Fields<T> = {
  [K in keyof T as string extends K
    ? never
    : number extends K
      ? never
      : K]: T[K];
};
/** Harness content bodies may be owned Attachments instead of uploaded references. */
export type HarnessValue<T> = T extends string | number | boolean | null | undefined
  ? T
  : T extends ContentReference
    ? ContentReference | Attachment
    : T extends readonly (infer V)[]
      ? HarnessValue<V>[]
      : T extends object
        ? keyof Fields<T> extends never
          ? T
          : { [K in keyof Fields<T>]: HarnessValue<Fields<T>[K]> }
        : T;
export type HarnessEvent<K extends EventType = EventType> =
  HarnessValue<Extract<Event, { type: K }>>;
/** Passing an Attachment transfers its invocation ownership to the SDK.
 * Keep host execution data separately; canonical effects carry accepted rewrites. */
export type BoundaryInput<K extends EventType> = K extends EventType
  ? Omit<HarnessEvent<K>, "type" | "source" | "harness" | "id" | "time" | "manifest"> & {
      id?: string;
      time?: string;
    }
  : never;
/** Generated schema-owned host facts with direct Attachment bodies. */
type DirectHostValue<T> = T extends OwnedAttachment<unknown>
  ? Attachment
  : T extends readonly (infer V)[] ? DirectHostValue<V>[]
  : T extends object ? { [P in keyof T]: DirectHostValue<T[P]> } : T;
export type EventInput<K extends EventType> = DirectHostValue<HostEventInputs<Attachment>[K]>;
/** Explicit delivery authority for one event. Effects remain separately granted. */
export interface HooksOptions {
  source: string;
  /** Required emitting harness identity, copied for all events. */
  harness: Harness;
  /** Typed event declarations. Omitted events and facilities grant nothing. */
  capabilities: HostCapabilities;
  /** Static non-event advertisements. Event grants always come from capabilities.
   * Opaque extension data is not content and is never traversed for attachments. */
  manifestMetadata?: Omit<StaticCapabilityManifest, "events"> & { events?: never };
  auth?: DeliveryAuthProvider;
  /** Header sources are separate from bearer authentication. Defaults to host env
   * lookup; valueRef requires this harness-owned resolver. */
  headerResolver?: import("./headers.js").HeaderResolver;
  /** Trusted HTTP network adapter (for example, host-managed TLS). The SDK still
   * owns protocol/authentication and cancellation. Scope transport credentials
   * to their exact destination; upload requests must not inherit event TLS identity.
   * OAuth discovery/token requests use the separate auth({ fetch }) override. */
  fetch?: typeof globalThis.fetch;
  /** Bound the immutable raw-content snapshot held by each boundary. */
  maxContentBytes?: number;
  /** Authorized attachment transfer concurrency across all calls on this Hooks
   * instance. Includes upload preparation, not result reads. Positive integer; default 8. */
  maxConcurrentUploads?: number;
  /** Best-effort observation budget, bounded by the operation signal. */
  observationTimeoutMs?: number;
  /** Start stdio backends with the full host environment rather than the minimal
   * base environment (PATH, HOME, locale, temp dirs, ...). Registration `env`
   * entries apply on top either way. Default false. */
  inheritEnvironment?: boolean;
}
export interface BoundaryOptions<Arguments = unknown, Result = unknown, P = unknown> {
  /** Optional caller contracts run during admission, before any publication. */
  contracts?: BoundaryContracts<Arguments, Result, P>;
  /** Generated named slots bind owned sources to producer descriptors, without refs. */
  contentSources?: readonly ContentSourceBinding<
    Attachment
  >[];
  /** Canonical pending state before any interceptor runs. */
  initialState?: InterceptRequest["params"]["state"];
  /** One operation budget: queue, authentication, content, delivery and observations. */
  signal?: AbortSignal;
  /** Complete narrowed advertisement; omitted controls stay absent. */
  capabilities?: Capabilities;
}
/** Structured SDK delivery evidence; messages and credential material are excluded. */
export interface DeliveryDiagnostic {
  backendId: string;
  subscriptionIndex: number;
  phase: "preparation" | "interception" | "observation";
  code: DeliveryDiagnosticCode;
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
export type BoundaryState<K extends EventType = EventType> = ReadonlyState<
  K extends "context.compact.before" ? TextState
    : K extends "model.request.before" ? MessagesState
    : K extends "user.elicitation.request" ? ElicitResultState
    : ToolState
>;
export type AcceptedResponse<K extends EventType = EventType> = K extends keyof EventResponses
  ? ResponseFor<K> : InterceptResponse;
type ResidualEffect<E> = E extends { type: "modify" | "return" } ? never : E;
type BoundaryEffects<K extends EventType> = ResidualEffect<K extends keyof EventResponses
  ? NonNullable<ResponseFor<K>["result"]["effects"]>[number]
  : NonNullable<InterceptResponse["result"]["effects"]>[number]>[];
export interface BoundaryResult<K extends EventType = EventType> {
  /** Present for owned Attachments. Effective local bodies by content item id,
   * including unread lazy sources. Close explicitly, independently of Hooks. */
  readonly content?: AttachmentContent;
  /** Authoritative decoded effective event. Local attachment bodies select
   * metadata; owned bytes remain available through content. Unknown extras survive. */
  readonly event: Extract<Event, { type: K }>;
  /** Residual effects to enact. Edits live in event and returns in state.candidate;
   * complete receiver effects remain in acceptedResponses. */
  readonly effects: Readonly<BoundaryEffects<K>>;
  /** Complete decoded receiver responses, in acceptance order, including opaque
   * envelope extras. Failed atomic responses are not accepted. */
  readonly acceptedResponses: readonly AcceptedResponse<K>[];
  /** Detached, deeply frozen canonical state; no effects replay is needed.
   * An interrupted boundary must not execute, even if earlier accepted state
   * contains a candidate or permission. With no acceptance, initialState is
   * preserved (or the neutral candidate/permission state is returned). */
  readonly state: BoundaryState<K>;
  /** All interception and observation delivery diagnostics. */
  diagnostics: DeliveryDiagnostic[];
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
