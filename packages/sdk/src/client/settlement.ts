import { parseEvent, parseInterceptRequest, responseForRequest } from "../draft/raw.js";
import type { Event, EventType, InterceptRequest, InterceptResponse } from "../draft/raw.js";
import { mapParts } from "./content-paths.js";
import { ContentSource } from "./content.js";
import { validateWire } from "./validation.js";


/** A consumer decode failed. Canonical acceptance evidence remains available,
 * but this error is not an outcome and does not authorize host execution. */
export class SettlementDecodeError extends Error {
  readonly code = "INVALID_SETTLEMENT";
  constructor(message: string,
    readonly acceptedResponses: readonly InterceptResponse[] = [],
    readonly canonicalState: unknown = undefined,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "SettlementDecodeError";
  }
}

/** Decode a schema-owned settlement without reading or uploading local bodies.
 * Local body ownership remains on `event`/`content`; the canonical view selects
 * metadata for those bodies. Unknown JSON fields are decoded losslessly. */
export function decodeSettledEvent<K extends EventType>(event: unknown): Extract<Event, { type: K }> {
  const metadata = mapParts(event, part => {
    if (part === null || typeof part !== "object") return part;
    if (part.kind === "text" && typeof part.text === "string" && part.selection === undefined)
      return { ...part, selection: "body" };
    if (!(part.body instanceof ReadableStream) && !(part.body instanceof ContentSource)) return part;
    const { body: _, ...rest } = part;
    return { ...rest, selection: "metadata" };
  });
  // Native host data is not part of the schema-owned consumer decode.
  const native = metadata.native;
  const hasNative = Object.hasOwn(metadata, "native");
  delete metadata.native;
  const decoded = parseEvent(metadata);
  if (!decoded.ok || validateWire("observe-notification", {
    jsonrpc: "2.0", method: "hooks/observe",
    params: { protocolVersion: "draft", event: metadata },
  }).length) throw new SettlementDecodeError("Invalid decoded settlement event");
  if (hasNative) decoded.value.native = native;
  return decoded.value as Extract<Event, { type: K }>;
}

/** Validate origin-correlated pending state before atomic publication. */
export function decodeSettledState(event: Event, value: InterceptRequest["params"]["state"]) {
  const state = value ?? { candidate: null, permission: "none" };
  // Observation-only events have no intercept-request variant. Decode their
  // generic ToolState through a neutral, schema-owned context, not a fabricated
  // intercept delivery for the originating observation.
  const interceptable = responseForRequest(event.type, {
    jsonrpc: "2.0", id: event.id, result: { protocolVersion: "draft", effects: [] },
  }).ok;
  const schemaEvent: Record<string, unknown> = interceptable ? { ...(event as unknown as Record<string, unknown>) } : {
    type: "tool.before", id: event.id, time: event.time, source: event.source,
    path: "native", call: { id: "state" }, tool: { name: "state", origin: "native", input: {} },
  };
  delete schemaEvent.native;
  const request = {
    jsonrpc: "2.0", id: event.id, method: "hooks/intercept",
    params: { protocolVersion: "draft", event: schemaEvent, state, capabilities: { effects: [] } },
  };
  const decoded = parseInterceptRequest(request);
  if (!decoded.ok || validateWire("intercept-request", request).length)
    throw new SettlementDecodeError("Invalid decoded settlement state");
  // The generic state union cannot express originating-event correlation.
  // The generated contextual response decoder provides that authority.
  if (["context.compact.before", "model.request.before", "user.elicitation.request"].includes(event.type) &&
      state.candidate !== null && !responseForRequest(event.type, {
    jsonrpc: "2.0", id: event.id,
    result: { protocolVersion: "draft", effects: [{ type: "return", value: state.candidate.value }] },
  }).ok) throw new SettlementDecodeError("Invalid origin-correlated settlement candidate");
  return decoded.value.params.state!;
}
