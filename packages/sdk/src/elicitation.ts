import { responseForRequest } from "./draft/raw.js";
import { parseJson } from "./json.js";
/** MCP 2025-11-25 inline-text binding. Identity comes from authentication,
 * never event.source or elicitation.server. */
export function validateElicitationExchange(
  request: any,
  result: any,
  validate: (schema: string, value: unknown) => void,
  principal: string,
  effect?: { type: string; target?: string; operation?: string },
): Record<string, unknown> {
  if (!principal) throw Error("Authenticated principal required");
  for (const envelope of [request, result]) {
    validate("intercept-request", envelope);
    if (envelope.id !== envelope.params.event.id)
      throw Error("Request/event ID mismatch");
  }
  if (
    request.params.event.type !== "user.elicitation.request" ||
    result.params.event.type !== "user.elicitation.result"
  )
    throw Error("Wrong elicitation boundary");
  validateElicitationCorrelation(request, result);
  const req = request.params.event.elicitation,
    res = result.params.event.elicitation;
  const payload = readSelectedElicitation(req, "request", validate);
  const answer = readSelectedElicitation(res, "result", validate);
  if (req.mode !== res.mode || req.server !== res.server)
    throw Error("Normalized metadata mismatch");
  if (payload === null || answer === null) {
    if (effect !== undefined) throw Error("Effects require selected bodies");
    return {
      selection: {
        request: req.request?.selection ?? "omit",
        result: res.result?.selection ?? "omit",
      },
      bodyValidation: "not-selected",
      provenance: { kind: "mcp", authenticatedSource: principal },
      externalCompletion: false,
    };
  }
  validateElicitationAnswer(payload, answer, validate);
  const mode = payload.mode ?? "form";
  if (
    req.mode !== mode ||
    res.mode !== mode ||
    req.server !== res.server ||
    res.action !== answer.action
  )
    throw Error("Normalized metadata mismatch");
  if ((mode === "url" || answer.action !== "accept") && "content" in answer)
    throw Error("Content is only permitted for accepted forms");
  let provenance: Record<string, string> = {
    kind: "mcp",
    authenticatedSource: principal,
  };
  if (effect !== undefined) {
    const kind = effect.type,
      boundary = kind === "modify" ? result : request;
    const admitted = responseForRequest(boundary.params.event.type, {
      jsonrpc: "2.0", id: boundary.id,
      result: { protocolVersion: "draft", effects: [effect] },
    });
    if (!admitted.ok) throw Error("Invalid contextual elicitation effect");
    validate("effect", effect);
    if (
      !["return", "deny", "modify"].includes(kind) ||
      !boundary.params.capabilities.effects.includes(kind)
    )
      throw Error("Effect not granted at this boundary");
    if (
      kind === "modify" &&
      (effect.target !== "content" ||
        !["replace", "merge"].includes(effect.operation ?? "") ||
        boundary.params.capabilities.modify?.content?.[
          effect.operation ?? ""
        ] !== true)
    )
      throw Error("Modify target/operation not granted");
    provenance = { kind: "hook", authenticatedSource: principal, effect: kind };
  }
  return structuredClone({
    request: payload,
    result: answer,
    provenance,
    externalCompletion: false,
  });
}

export function validateElicitationAnswer(
  request: any,
  answer: any,
  validate: (name: string, value: any) => void,
): void {
  validate("mcp-elicitation#result", answer);
  const mode = request.mode ?? "form";
  if ((mode === "url" || answer.action !== "accept") && "content" in answer)
    throw Error("Content is only permitted for accepted forms");
  if (mode === "form" && answer.action === "accept")
    validate("form-answer", {
      schema: request.requestedSchema,
      value: answer.content ?? {},
    });
}

export function validateElicitationMode(
  mode: string,
  capabilities?: Record<string, unknown>,
  origin = "ahp",
): Record<string, unknown> {
  if (!["ahp", "mcp"].includes(origin) || !["form", "url"].includes(mode))
    throw Error("Unknown origin or mode");
  let caps = structuredClone(capabilities ?? {});
  if (
    typeof caps !== "object" ||
    caps === null ||
    Array.isArray(caps) ||
    Object.entries(caps).some(
      ([k, v]) =>
        ["form", "url"].includes(k) &&
        (typeof v !== "object" || v === null || Array.isArray(v)),
    )
  )
    throw Error("Invalid elicitation capabilities");
  if (
    origin === "mcp" &&
    capabilities !== undefined &&
    Object.keys(capabilities).length === 0
  )
    caps = { form: {} };
  if (!(mode in caps)) throw Error("Elicitation mode not registered");
  return caps;
}

/** Metadata and omit never resolve or parse content. Selected gaps fail closed. */
export function readSelectedElicitation(
  meta: any,
  stage: "request" | "result",
  validate: (schema: string, value: any) => void,
): any | null {
  const item = meta[stage];
  if (item === undefined) return null;
  validate("content-item", item);
  if (item.kind !== "text" || item.mediaType !== "text/plain")
    throw Error("MCP body must be an ordinary text part");
  if (item.selection !== "body") return null;
  if (item.gap !== undefined || typeof item.text !== "string")
    throw Error("Selected text unavailable (fail closed)");
  const payload = parseJson(item.text) as Record<string, any>;
  validate("mcp-elicitation#" + stage, payload);
  if (stage === "request" && meta.mode !== (payload.mode ?? "form"))
    throw Error("Mode mismatch");
  if (stage === "result") {
    if (meta.action !== payload.action) throw Error("Action mismatch");
    if (
      (meta.mode === "url" || payload.action !== "accept") &&
      "content" in payload
    )
      throw Error("Forbidden content");
  }
  return payload;
}

/** Require source-scoped parent identity and identical session scope before IO. */
export function validateElicitationCorrelation(
  request: any,
  result: any,
): void {
  const req = request.params.event,
    res = result.params.event;
  if (
    typeof res.parentEventId !== "string" ||
    res.parentEventId !== req.id ||
    res.source !== req.source ||
    res.session?.id !== req.session?.id
  )
    throw Error("Elicitation parent/source/session mismatch");
}
