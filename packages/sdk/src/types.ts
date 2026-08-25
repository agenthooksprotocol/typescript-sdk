export const PROTOCOL_VERSION = "0.1" as const;
export const INTERCEPT_METHOD = "hooks/intercept" as const;
export const TOOL_KINDS = [
  "shell",
  "file_read",
  "file_write",
  "file_edit",
  "search",
  "fetch",
  "task",
  "mcp",
  "other",
] as const;

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export type JsonObject = { [key: string]: JsonValue };
export type ToolKind = (typeof TOOL_KINDS)[number];

export interface SessionContext {
  id: string;
  cwd?: string;
  workspaceRoots?: string[];
  model?: string;
  agent?: { id: string; type?: string };
}

export interface ToolContext {
  callId: string;
  name: string;
  kind: ToolKind;
  input: JsonObject;
  mcp?: JsonObject;
}

export interface NativeContext {
  provider: string;
  eventName: string;
  payload: JsonObject;
}

export interface ToolBeforeEvent {
  id: string;
  source: string;
  type: "tool.before";
  time: string;
  session: SessionContext;
  tool: ToolContext;
  native?: NativeContext;
  extensions?: JsonObject;
}

export interface InterceptRequest {
  jsonrpc: "2.0";
  id: string;
  method: "hooks/intercept";
  params: {
    protocolVersion: "0.1";
    event: ToolBeforeEvent;
    capabilities: { effects: ["deny"] };
  };
}

export type DenyEffect = { type: "deny"; reason: string; code?: string; extensions?: JsonObject };
export type InterceptResult =
  | { protocolVersion: "0.1"; effects: [] }
  | { protocolVersion: "0.1"; effects: [DenyEffect] };

export interface InterceptResponse {
  jsonrpc: "2.0";
  id: string;
  result: InterceptResult;
}

export type FailurePolicy = "fail-open" | "fail-closed";
export type Lifecycle = "per_event" | "persistent";

export interface HookBackend {
  command: string;
  args?: readonly string[];
  timeoutMs: number;
  failurePolicy: FailurePolicy;
  retries?: number;
  lifecycle?: Lifecycle;
  name?: string;
}

export interface ToolBeforeInput {
  source: string;
  eventId?: string;
  time?: string;
  session: Omit<SessionContext, "id"> & { id?: string };
  tool: Omit<ToolContext, "callId"> & { callId?: string };
  native?: NativeContext;
  extensions?: JsonObject;
}

export interface HookFailure {
  backend: string;
  policy: FailurePolicy;
  code: string;
  message: string;
}

export interface ToolBeforeOutcome {
  decision: "continue" | "deny";
  event: ToolBeforeEvent;
  failures: HookFailure[];
  denial?: { backend: string; reason: string; code?: string; extensions?: JsonObject; operational: boolean };
}

export type IdKind = "event" | "session" | "call";
export type IdGenerator = (kind: IdKind) => string;
