import {
  validateCapabilitiesRequest,
  validateCapabilitiesResponse,
  validateInterceptRequest,
  validateInterceptResponse,
} from "../draft/index.js";
import {
  PROTOCOL_VERSION,
  parseObserveNotification,
  type CapabilitiesRequest,
  type CapabilitiesResponse,
  type InterceptRequest,
  type InterceptResponse,
  type ObserveNotification,
} from "../draft/generated.js";
import { validateWire } from "../client/validation.js";

/** A decoded canonical wire message, not a host execution boundary. */
export type Message =
  | InterceptRequest
  | ObserveNotification
  | CapabilitiesRequest;
type ResultFields<T> = {
  [K in keyof T as string extends K
    ? never
    : K extends "protocolVersion"
      ? never
      : K]: T[K];
};
export type InterceptResult = ResultFields<InterceptResponse["result"]>;
export type CapabilitiesResult = ResultFields<CapabilitiesResponse["result"]>;
export type Handler = (
  message: Message,
) =>
  | InterceptResult
  | CapabilitiesResult
  | void
  | Promise<InterceptResult | CapabilitiesResult | void>;

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
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
): Response {
  return notification
    ? new Response(null, { status: status === 200 ? 500 : status })
    : json({ jsonrpc: "2.0", id, error: { code, message } }, status);
}

/** Check support without executing, resolving bodies, or composing host state. */
function supported(
  request: InterceptRequest,
  response: InterceptResponse,
): boolean {
  const caps = request.params.capabilities;
  return response.result.effects.every((effect) => {
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
          typeof flow.remainingContinuations === "number" &&
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
 * Observe callbacks return void. No notification receives a JSON-RPC reply.
 * HTTP framing errors use 4xx; evaluated RPC failures use 200. Exceptions and
 * invalid callback results are replaced by fixed, credential-free errors.
 */
async function handle(request: Request, handler: Handler): Promise<Response> {
  if (request.method !== "POST")
    return new Response(null, { status: 405, headers: { allow: "POST" } });
  if (
    request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !==
    "application/json"
  )
    return new Response(null, { status: 415 });
  let raw: unknown;
  try {
    raw = JSON.parse(await request.text()) as unknown;
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
    const result = await handler(message);
    if (canonical.method === "hooks/observe")
      return new Response(null, { status: result === undefined ? 204 : 500 });
    if (!object(result) || Object.hasOwn(result, "protocolVersion"))
      throw new Error("Invalid result");
    const envelope = {
      jsonrpc: "2.0",
      id: canonical.id,
      result: { ...result, protocolVersion: PROTOCOL_VERSION },
    };
    if (canonical.method === "hooks/intercept") {
      const response = validateInterceptResponse(envelope);
      if (!response.ok || !supported(canonical, response.value))
        throw new Error("Invalid result");
      return json(response.value);
    }
    const response = validateCapabilitiesResponse(envelope);
    if (!response.ok) throw new Error("Invalid result");
    return json(response.value);
  } catch {
    return error(id, -32004, "Backend internal error", notification);
  }
}

export const hooks = { handle };
