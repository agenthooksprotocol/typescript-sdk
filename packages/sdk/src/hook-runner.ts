import { randomUUID } from "node:crypto";
import { HookOperationalError, asOperationalError } from "./errors.js";
import { createTransport, type LineTransport } from "./transport.js";
import { INTERCEPT_METHOD, PROTOCOL_VERSION, type HookBackend, type HookFailure, type IdGenerator, type InterceptRequest, type ToolBeforeEvent, type ToolBeforeInput, type ToolBeforeOutcome } from "./types.js";
import { assertJsonObject, parseInterceptRequest, parseInterceptResponse } from "./validation.js";

interface Registration {
  config: Required<Pick<HookBackend, "command" | "args" | "timeoutMs" | "failurePolicy" | "retries" | "lifecycle">> & Pick<HookBackend, "name">;
  transport: LineTransport;
}

function validateBackend(backend: HookBackend): Registration["config"] {
  if (backend === null || typeof backend !== "object") throw new HookOperationalError("INVALID_CONFIG", "Backend configuration must be an object");
  if (typeof backend.command !== "string" || backend.command.length === 0) throw new HookOperationalError("INVALID_CONFIG", "Backend command must be a non-empty string");
  const args = backend.args === undefined ? [] : [...backend.args];
  if (!args.every((arg) => typeof arg === "string")) throw new HookOperationalError("INVALID_CONFIG", "Backend args must be strings");
  if (!Number.isInteger(backend.timeoutMs) || backend.timeoutMs <= 0) throw new HookOperationalError("INVALID_CONFIG", "Backend timeoutMs must be a positive integer");
  if (backend.failurePolicy !== "fail-open" && backend.failurePolicy !== "fail-closed") throw new HookOperationalError("INVALID_CONFIG", "Backend failurePolicy must be explicit");
  const retries = backend.retries ?? 0;
  if (!Number.isInteger(retries) || retries < 0 || retries > 10) throw new HookOperationalError("INVALID_CONFIG", "Backend retries must be an integer from 0 through 10");
  const lifecycle = backend.lifecycle ?? "per_event";
  if (lifecycle !== "per_event" && lifecycle !== "persistent") throw new HookOperationalError("INVALID_CONFIG", "Unsupported lifecycle");
  return backend.name === undefined
    ? { command: backend.command, args, timeoutMs: backend.timeoutMs, failurePolicy: backend.failurePolicy, retries, lifecycle }
    : { command: backend.command, args, timeoutMs: backend.timeoutMs, failurePolicy: backend.failurePolicy, retries, lifecycle, name: backend.name };
}

function snapshot<T>(value: T, label: string): T {
  assertJsonObject(value, label);
  return JSON.parse(JSON.stringify(value)) as T;
}

export class ToolBeforeRunner {
  readonly #ids: IdGenerator;
  readonly #registrations: Registration[] = [];
  #tail: Promise<void> = Promise.resolve();

  constructor(options: { idGenerator?: IdGenerator } = {}) {
    this.#ids = options.idGenerator ?? ((kind) => `${kind}_${randomUUID()}`);
  }

  register(backend: HookBackend): () => void {
    const config = validateBackend(backend);
    const registration: Registration = { config, transport: createTransport(config.command, config.args, config.lifecycle) };
    this.#registrations.push(registration);
    return () => {
      const index = this.#registrations.indexOf(registration);
      if (index !== -1) this.#registrations.splice(index, 1);
      registration.transport.close();
    };
  }

  intercept(input: ToolBeforeInput): Promise<ToolBeforeOutcome> {
    const result = this.#tail.then(() => this.#interceptNow(input));
    this.#tail = result.then(() => undefined, () => undefined);
    return result;
  }

  async #interceptNow(input: ToolBeforeInput): Promise<ToolBeforeOutcome> {
    if (input === null || typeof input !== "object" || input.session === null || typeof input.session !== "object" || input.tool === null || typeof input.tool !== "object") {
      throw new HookOperationalError("INVALID_CONFIG", "Tool input, session, and tool must be objects");
    }
    const session = {
      id: this.#providedId(input.session.id, "session"),
      ...(input.session.cwd === undefined ? {} : { cwd: input.session.cwd }),
      ...(input.session.workspaceRoots === undefined ? {} : { workspaceRoots: input.session.workspaceRoots }),
      ...(input.session.model === undefined ? {} : { model: input.session.model }),
      ...(input.session.agent === undefined ? {} : { agent: input.session.agent }),
    };
    const tool = {
      callId: this.#providedId(input.tool.callId, "call"),
      name: input.tool.name,
      kind: input.tool.kind,
      input: snapshot(input.tool.input, "tool.input"),
      ...(input.tool.mcp === undefined ? {} : { mcp: snapshot(input.tool.mcp, "tool.mcp") }),
    };
    const event: ToolBeforeEvent = {
      id: this.#providedId(input.eventId, "event"),
      source: input.source,
      type: "tool.before",
      time: input.time ?? new Date().toISOString(),
      session,
      tool,
      ...(input.native === undefined ? {} : { native: snapshot(input.native, "native") }),
      ...(input.extensions === undefined ? {} : { extensions: snapshot(input.extensions, "extensions") }),
    };
    parseInterceptRequest(JSON.stringify({ jsonrpc: "2.0", id: event.id, method: INTERCEPT_METHOD, params: { protocolVersion: PROTOCOL_VERSION, event, capabilities: { effects: ["deny"] } } }));
    const failures: HookFailure[] = [];
    const registrations = [...this.#registrations];
    for (const registration of registrations) {
      const request: InterceptRequest = {
        jsonrpc: "2.0",
        id: event.id,
        method: INTERCEPT_METHOD,
        params: { protocolVersion: PROTOCOL_VERSION, event, capabilities: { effects: ["deny"] } },
      };
      const line = JSON.stringify(request);
      parseInterceptRequest(line);
      let lastError: HookOperationalError | undefined;
      const deadline = Date.now() + registration.config.timeoutMs;
      for (let attempt = 0; attempt <= registration.config.retries; attempt += 1) {
        const remainingMs = deadline - Date.now();
        if (remainingMs <= 0) {
          lastError = new HookOperationalError("TIMEOUT", `Hook exchange exceeded ${registration.config.timeoutMs} ms`);
          break;
        }
        try {
          const responseLine = await registration.transport.exchange(line, remainingMs);
          const response = parseInterceptResponse(responseLine, event.id);
          const effect = response.effects[0];
          if (effect !== undefined) {
            const denial = {
              backend: this.#backendName(registration),
              reason: effect.reason,
              operational: false,
              ...(effect.code === undefined ? {} : { code: effect.code }),
              ...(effect.extensions === undefined ? {} : { extensions: effect.extensions }),
            };
            return { decision: "deny", event, failures, denial };
          }
          lastError = undefined;
          break;
        } catch (error) {
          lastError = asOperationalError(error);
          registration.transport.close();
        }
      }
      if (lastError !== undefined) {
        const failure: HookFailure = { backend: this.#backendName(registration), policy: registration.config.failurePolicy, code: lastError.code, message: lastError.message };
        failures.push(failure);
        if (registration.config.failurePolicy === "fail-closed") {
          return { decision: "deny", event, failures, denial: { backend: failure.backend, reason: `Operational failure: ${failure.code}`, operational: true } };
        }
      }
    }
    return { decision: "continue", event, failures };
  }

  #providedId(value: string | undefined, kind: "event" | "session" | "call"): string {
    if (value !== undefined) {
      if (typeof value !== "string" || value.length === 0) throw new HookOperationalError("INVALID_CONFIG", `${kind} ID must be a non-empty string`);
      return value;
    }
    return this.#generatedId(kind);
  }

  #generatedId(kind: "event" | "session" | "call"): string {
    const value = this.#ids(kind);
    if (typeof value !== "string" || value.length === 0) throw new HookOperationalError("INVALID_CONFIG", `Generated ${kind} ID must be a non-empty string`);
    return value;
  }

  #backendName(registration: Registration): string { return registration.config.name ?? registration.config.command; }

  close(): void {
    for (const registration of this.#registrations) registration.transport.close();
    this.#registrations.length = 0;
  }
}
