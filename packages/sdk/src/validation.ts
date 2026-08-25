import { HookOperationalError } from "./errors.js";
import { INTERCEPT_METHOD, PROTOCOL_VERSION, TOOL_KINDS, type InterceptRequest, type InterceptResult, type JsonObject, type JsonValue } from "./types.js";

type RecordValue = Record<string, unknown>;

function record(value: unknown, label: string): RecordValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} must be an object`);
  }
  return value as RecordValue;
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} must be a non-empty string`);
  }
  return value;
}

function optionalString(value: RecordValue, key: string, label: string): void {
  if (key in value) nonEmptyString(value[key], `${label}.${key}`);
}

function assertUri(value: unknown, label: string): void {
  const text = nonEmptyString(value, label);
  try {
    new URL(text);
  } catch (error) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} must be an absolute URI`, { cause: error });
  }
}

export function assertJsonValue(value: unknown, label = "value"): asserts value is JsonValue {
  assertJsonValueInner(value, label, new WeakSet<object>());
}

export function assertJsonObject(value: unknown, label = "value"): asserts value is JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} must be a JSON object`);
  }
  assertJsonValue(value, label);
}

function assertJsonValueInner(value: unknown, label: string, seen: WeakSet<object>): void {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value !== "object") throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} is not a JSON value`);
  if (seen.has(value)) throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} contains a cycle`);
  seen.add(value);
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value).filter((key) => key !== "length");
    if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
      throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} must be a dense JSON array`);
    }
    for (let index = 0; index < value.length; index += 1) assertJsonValueInner(value[index], `${label}[${index}]`, seen);
  } else {
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null) throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} must be a plain JSON object`);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} cannot have symbol keys`);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        throw new HookOperationalError("MALFORMED_JSON_RPC", `${label}.${key} must be an enumerable data property`);
      }
      assertJsonValueInner(descriptor.value, `${label}.${key}`, seen);
    }
  }
  seen.delete(value);
}

function assertRfc3339(value: unknown, label: string): void {
  const text = nonEmptyString(value, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(text) || !Number.isFinite(Date.parse(text))) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} must be an RFC 3339 timestamp`);
  }
}

function isReverseDns(value: string): boolean {
  return /^(?:[A-Za-z][A-Za-z0-9-]*\.)+[A-Za-z][A-Za-z0-9_.-]*$/.test(value);
}

function assertExtensions(value: unknown, label: string): asserts value is JsonObject {
  assertJsonObject(value, label);
  for (const key of Object.keys(value)) {
    if (!isReverseDns(key)) throw new HookOperationalError("MALFORMED_JSON_RPC", `${label} keys must use reverse-DNS names`);
  }
}

export function parseJson(line: string): unknown {
  try {
    return JSON.parse(line) as unknown;
  } catch (error) {
    throw new HookOperationalError("MALFORMED_JSON", "Message is not valid JSON", { cause: error });
  }
}

export function parseInterceptRequest(line: string): InterceptRequest {
  const parsed = parseJson(line);
  const root = record(parsed, "request");
  if (root.jsonrpc !== "2.0" || root.method !== INTERCEPT_METHOD) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", "Expected JSON-RPC 2.0 hooks/intercept request");
  }
  const requestId = nonEmptyString(root.id, "request.id");
  const params = record(root.params, "request.params");
  if (params.protocolVersion !== PROTOCOL_VERSION) throw new HookOperationalError("INCOMPATIBLE_VERSION", "Expected protocolVersion 0.1");
  const capabilities = record(params.capabilities, "request.params.capabilities");
  if (!Array.isArray(capabilities.effects) || capabilities.effects.length !== 1 || capabilities.effects[0] !== "deny") {
    throw new HookOperationalError("UNSUPPORTED_EFFECT", "capabilities.effects must be exactly [\"deny\"]");
  }
  const event = record(params.event, "request.params.event");
  const eventId = nonEmptyString(event.id, "event.id");
  if (requestId !== eventId) throw new HookOperationalError("ID_MISMATCH", "JSON-RPC request ID must equal event.id");
  assertUri(event.source, "event.source");
  if (event.type !== "tool.before") throw new HookOperationalError("UNSUPPORTED_EVENT", "event.type must be tool.before");
  assertRfc3339(event.time, "event.time");
  const session = record(event.session, "event.session");
  nonEmptyString(session.id, "event.session.id");
  optionalString(session, "cwd", "event.session");
  optionalString(session, "model", "event.session");
  if ("agent" in session) {
    const agent = record(session.agent, "event.session.agent");
    nonEmptyString(agent.id, "event.session.agent.id");
    optionalString(agent, "type", "event.session.agent");
  }
  if ("workspaceRoots" in session && (!Array.isArray(session.workspaceRoots) || !session.workspaceRoots.every((root) => typeof root === "string" && root.length > 0))) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", "event.session.workspaceRoots must be an array of non-empty strings");
  }
  const tool = record(event.tool, "event.tool");
  nonEmptyString(tool.callId, "event.tool.callId");
  nonEmptyString(tool.name, "event.tool.name");
  if (typeof tool.kind !== "string" || !(TOOL_KINDS as readonly string[]).includes(tool.kind)) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", `Unknown event.tool.kind: ${String(tool.kind)}`);
  }
  assertJsonObject(tool.input, "event.tool.input");
  if ("mcp" in tool) assertJsonObject(tool.mcp, "event.tool.mcp");
  if ("native" in event) {
    const native = record(event.native, "event.native");
    nonEmptyString(native.provider, "event.native.provider");
    nonEmptyString(native.eventName, "event.native.eventName");
    assertJsonObject(native.payload, "event.native.payload");
  }
  if ("extensions" in event) assertExtensions(event.extensions, "event.extensions");
  return parsed as InterceptRequest;
}

export function parseInterceptResponse(line: string, expectedId: string): InterceptResult {
  const root = record(parseJson(line), "response");
  if (root.jsonrpc !== "2.0") throw new HookOperationalError("MALFORMED_JSON_RPC", "response.jsonrpc must be 2.0");
  if (root.id !== expectedId) throw new HookOperationalError("ID_MISMATCH", "Response ID does not match request ID");
  if ("error" in root && "result" in root) throw new HookOperationalError("MALFORMED_JSON_RPC", "Response cannot contain both result and error");
  if ("error" in root) {
    const rpcError = record(root.error, "response.error");
    if (!Number.isInteger(rpcError.code) || typeof rpcError.message !== "string") {
      throw new HookOperationalError("MALFORMED_JSON_RPC", "Malformed JSON-RPC error object");
    }
    if ("data" in rpcError) assertJsonValue(rpcError.data, "response.error.data");
    throw new HookOperationalError("JSON_RPC_ERROR", `Backend JSON-RPC error ${String(rpcError.code)}: ${rpcError.message}`);
  }
  if (!("result" in root)) throw new HookOperationalError("MALFORMED_JSON_RPC", "Response must contain result or error");
  const result = record(root.result, "response.result");
  if (result.protocolVersion !== PROTOCOL_VERSION) throw new HookOperationalError("INCOMPATIBLE_VERSION", "Backend protocolVersion is not 0.1");
  if (!Array.isArray(result.effects)) throw new HookOperationalError("MALFORMED_JSON_RPC", "response.result.effects must be an array");
  if (result.effects.length > 1) throw new HookOperationalError("MULTIPLE_EFFECTS", "tool.before permits at most one effect");
  if (result.effects.length === 0) return { protocolVersion: PROTOCOL_VERSION, effects: [] };
  const effect = record(result.effects[0], "response.result.effects[0]");
  if (effect.type !== "deny") throw new HookOperationalError("UNSUPPORTED_EFFECT", `Unsupported tool.before effect: ${String(effect.type)}`);
  const reason = nonEmptyString(effect.reason, "response.result.effects[0].reason");
  if ("code" in effect && (typeof effect.code !== "string" || !isReverseDns(effect.code))) {
    throw new HookOperationalError("MALFORMED_JSON_RPC", "Deny effect code must use reverse-DNS notation");
  }
  if ("extensions" in effect) assertExtensions(effect.extensions, "response.result.effects[0].extensions");
  const deny = { type: "deny" as const, reason, ...(effect.code === undefined ? {} : { code: effect.code as string }), ...(effect.extensions === undefined ? {} : { extensions: effect.extensions as JsonObject }) };
  return { protocolVersion: PROTOCOL_VERSION, effects: [deny] };
}
