import type { Configuration } from "../draft/raw.js";
import type { Capabilities, CapabilitiesRequest, CapabilitiesResponse, Event, EventResponses, EventType, InterceptRequest, ObserveNotification, ResponseFor, events } from '../draft/raw.js';

type EventNames = typeof events;
type InterceptEvent = keyof EventResponses;
type Awaitable<T> = T | Promise<T>;
type CapabilityReplyFields = {
  [K in keyof CapabilitiesResponse['result'] as string extends K ? never
    : K extends 'protocolVersion' ? never : K]: CapabilitiesResponse['result'][K];
};
type CapabilitiesReply = CapabilityReplyFields & {
  readonly protocolVersion?: never;
  readonly [extension: string]: unknown;
};
type AtLeastOne<T> = { [K in keyof T]-?: Required<Pick<T, K>> & Partial<Omit<T, K>> }[keyof T];

/** Application context. Dynamic request grants still govern response admission. */
export interface InterceptContext<K extends InterceptEvent> {
  readonly event: Extract<Event, { type: K }>;
  readonly capabilities: Capabilities;
  readonly state: InterceptRequest['params']['state'];
  readonly request: Omit<InterceptRequest, 'params'> & {
    readonly params: Omit<InterceptRequest['params'], 'event'> & { readonly event: Extract<Event, { type: K }> };
  };
  readonly signal: AbortSignal;
}
export interface ObservationContext<K extends EventType> {
  readonly event: Extract<Event, { type: K }>;
  readonly notification: Omit<ObserveNotification, 'params'> & {
    readonly params: Omit<ObserveNotification['params'], 'event'> & { readonly event: Extract<Event, { type: K }> };
  };
  readonly signal: AbortSignal;
}
/** Empty replies are no-ops. Correlation and protocol version belong to the server. */
export type ServerReply<K extends InterceptEvent> = {
  readonly effects?: readonly NonNullable<ResponseFor<K>['result']['effects']>[number][];
  readonly protocolVersion?: never;
  readonly [extension: string]: unknown;
};
/** Observation context for any event; narrow with `ctx.event.type`. */
export type AnyObservationContext = { [K in EventType]: ObservationContext<K> }[EventType];
type ObserveEntries = {
  readonly [N in keyof EventNames]?: (context: ObservationContext<EventNames[N]>) => void | Promise<void>;
} & {
  /** Catch-all observer, invoked only for events without their own observer. */
  readonly any?: (context: AnyObservationContext) => void | Promise<void>;
};
export type ServerObserveHandlers = AtLeastOne<ObserveEntries>;
export type ServerInterceptHandlers = AtLeastOne<{
  readonly [N in keyof EventNames as EventNames[N] extends InterceptEvent ? N : never]?:
    EventNames[N] extends InterceptEvent
      ? (context: InterceptContext<EventNames[N]>) => Awaitable<ServerReply<EventNames[N]>>
      : never;
}>;
export type ServerHandlers = AtLeastOne<{
  readonly configuration?: Configuration;
  readonly intercept?: ServerInterceptHandlers;
  readonly observe?: ServerObserveHandlers;
  readonly capabilities?: (context: { readonly request: CapabilitiesRequest; readonly signal: AbortSignal }) => Awaitable<CapabilitiesReply>;
}>;
