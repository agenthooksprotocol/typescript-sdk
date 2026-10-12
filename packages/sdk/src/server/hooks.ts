import {
  validateCapabilitiesRequest,
  validateCapabilitiesResponse,
  validateInterceptRequest,
  validateInterceptResponse,
} from "../draft/index.js";
import {
  PROTOCOL_VERSION,
  events,
  parseObserveNotification,
  responseForRequest,
  type EventResponses,
  type InterceptRequest,
} from "../draft/raw.js";
import { isEventType, validateWire } from "../client/validation.js";
import { parseJson, stringifyJson } from "../json.js";

import type { ServerHandlers } from "./types.js";

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function json(value: unknown, status = 200): Response {
  return new Response(stringifyJson(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}
function error(
  id: unknown,
  code: number,
  message: string,
  notification: boolean,
  status = 200,
  data?: unknown,
): Response {
  return notification
    ? new Response(null, { status: status === 200 ? 500 : status })
    : json(
        {
          jsonrpc: "2.0",
          id,
          error: data === undefined ? { code, message } : { code, message, data },
        },
        status,
      );
}

/** A fixed, credential-free JSON-RPC failure raised while evaluating a request. */
class Failure {
  constructor(
    readonly code: number,
    readonly message: string,
  ) {}
}
const methodNotFound = new Failure(-32601, "Method not found");
const unsupportedEvent = new Failure(-32002, "Unsupported event");
const backendInternal = new Failure(-32004, "Backend internal error");
const internalError = new Failure(-32603, "Internal error");

/** Run application code; any throw or rejection is a backend failure. */
async function invoke(callback: () => unknown): Promise<unknown> {
  try {
    return await callback();
  } catch {
    throw backendInternal;
  }
}

/** Check support without executing, resolving bodies, or composing host state. */
function supported(
  request: InterceptRequest,
  response: EventResponses[keyof EventResponses],
): boolean {
  const caps = request.params.capabilities;
  return (response.result.effects ?? []).every((effect) => {
    if (!caps.effects.includes(effect.type)) return false;
    if (effect.type === "modify") {
      const target = caps.modify?.[effect.target];
      return object(target) && target[effect.operation] === true;
    }
    if (effect.type === "inject") {
      return (
        caps.inject?.context.append === true &&
        caps.inject.context.deliverAt.includes(effect.deliverAt)
      );
    }
    if (effect.type === "flow") {
      if (!caps.flow?.operations.includes(effect.operation)) return false;
      if (effect.operation === "continue") {
        const flow = caps.flow;
        return (
          (typeof flow.remainingContinuations === "number" || typeof flow.remainingContinuations === "bigint") &&
          flow.remainingContinuations > 0 &&
          (flow.maxContinuations === undefined ||
            (flow.continuationCount ?? 0) < flow.maxContinuations)
        );
      }
    }
    if (
      effect.type === "return" &&
      request.params.event.type === "user.elicitation.request"
    ) {
      const elicitation = request.params.event.elicitation;
      if (!object(elicitation) || typeof elicitation.mode !== "string") return false;
      if (!caps.elicitation?.[elicitation.mode]) return false;
    }
    return true;
  });
}

/** Handle one HTTP POST. The application owns authentication and routing.
 * Observe callbacks return void. No notification receives a JSON-RPC reply; a
 * known observe event without an observer is accepted with 204.
 * HTTP framing errors use 4xx; evaluated RPC failures use 200. Missing
 * capabilities handlers are -32601, intercepts without a handler -32002,
 * callback exceptions and invalid callback results -32004, and SDK-internal
 * failures -32603, all with fixed, credential-free messages.
 */
async function handle(request: Request, handlers: ServerHandlers): Promise<Response> {
  if (request.method !== "POST")
    return new Response(null, { status: 405, headers: { allow: "POST" } });
  if (
    request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !==
    "application/json"
  )
    return new Response(null, { status: 415 });
  let raw: unknown;
  try {
    raw = parseJson(await request.text());
  } catch {
    return error(null, -32700, "Parse error", false, 400);
  }
  if (
    !object(raw) ||
    raw.jsonrpc !== "2.0" ||
    typeof raw.method !== "string" ||
    (Object.hasOwn(raw, "id") &&
      typeof raw.id !== "string" &&
      typeof raw.id !== "number" &&
      raw.id !== null)
  ) {
    return error(null, -32600, "Invalid Request", false, 400);
  }
  const notification = !Object.hasOwn(raw, "id");
  const id = notification ? null : raw.id;
  if (
    !["hooks/intercept", "hooks/observe", "hooks/capabilities"].includes(
      raw.method,
    )
  ) {
    return error(
      id,
      -32601,
      "Method not found",
      notification,
      notification ? 400 : 200,
    );
  }
  if (
    object(raw.params) &&
    typeof raw.params.protocolVersion === "string" &&
    raw.params.protocolVersion !== PROTOCOL_VERSION
  ) {
    return error(
      id,
      -32001,
      "Unsupported AHP protocol version",
      notification,
      notification ? 400 : 200,
      { supported: [PROTOCOL_VERSION] },
    );
  }
  try {
    // Validation and snapshots can exhaust the stack on deeply nested external JSON.
    const decoded =
      raw.method === "hooks/intercept"
        ? validateInterceptRequest(raw)
        : raw.method === "hooks/capabilities"
          ? validateCapabilitiesRequest(raw)
          : validateWire("observe-notification", raw).length === 0
            ? parseObserveNotification(raw)
            : { ok: false as const };
    if (!decoded.ok)
      return error(
        id,
        -32602,
        "Invalid params",
        notification,
        notification ? 400 : 200,
      );
    const message = decoded.value;
    // Retain trusted correlation and advertisements if application code mutates its message.
    const canonical = structuredClone(message);
    let result: unknown;
    if (message.method === "hooks/capabilities") {
      const callback = handlers.capabilities;
      if (!callback) throw methodNotFound;
      result = await invoke(() => callback({ request: message, signal: request.signal }));
    } else {
      const name = Object.entries(events).find(([, event]) => event === message.params.event.type)?.[0];
      if (!name) throw unsupportedEvent;
      if (message.method === "hooks/observe") {
        const observations = handlers.observe as Record<string, unknown> | undefined;
        const callback = observations?.[name];
        // A known event without an observer is accepted silently, like any notification.
        if (typeof callback !== "function") return new Response(null, { status: 204 });
        result = await invoke(() =>
          callback({ event: message.params.event, notification: message, signal: request.signal }));
      } else {
        const callbacks = handlers.intercept as Record<string, unknown> | undefined;
        const callback = callbacks?.[name];
        if (typeof callback !== "function") throw unsupportedEvent;
        result = await invoke(() =>
          callback({ event: message.params.event, capabilities: message.params.capabilities,
            state: message.params.state, request: message, signal: request.signal }));
      }
    }
    if (canonical.method === "hooks/observe")
      return new Response(null, { status: result === undefined ? 204 : 500 });
    // Application results that cannot be admitted, including non-JSON values that
    // exhaust validation, are backend failures.
    try {
      if (!object(result) || Object.hasOwn(result, "protocolVersion"))
        throw backendInternal;
      const envelope = {
        jsonrpc: "2.0",
        id: canonical.id,
        result: { ...result, protocolVersion: PROTOCOL_VERSION },
      };
      if (canonical.method === "hooks/intercept") {
        if (!isEventType(canonical.params.event.type)) throw internalError;
        const validation = validateInterceptResponse(envelope);
        const response = responseForRequest(canonical.params.event.type, envelope);
        if (!validation.ok || !response.ok || !supported(canonical, response.value))
          throw backendInternal;
        return json(response.value);
      }
      const response = validateCapabilitiesResponse(envelope);
      if (!response.ok) throw backendInternal;
      return json(response.value);
    } catch (caught) {
      throw caught instanceof Failure ? caught : backendInternal;
    }
  } catch (caught) {
    // Anything not attributed above (e.g. validator stack exhaustion) is an SDK-internal failure.
    const failure = caught instanceof Failure ? caught : internalError;
    return error(id, failure.code, failure.message, notification,
      notification && failure !== backendInternal ? 400 : 200);
  }
}

export const hooks = { handle };
