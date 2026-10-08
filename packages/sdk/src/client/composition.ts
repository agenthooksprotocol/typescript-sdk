import { Ajv2020 } from "ajv/dist/2020.js";
import { fullFormats } from "ajv-formats/dist/formats.js";
import { schemas } from "../draft/schemas.js";
import { validateElicitationAnswer } from "../elicitation.js";
import { validateEffect, validateInterceptResponse } from "../draft/index.js";
import type {
  Effect,
  Capabilities,
  InterceptResponse,
  InterceptRequest,
  ObserveNotification,
  JsonValue,
} from "../draft/generated.js";

export type ClientEvent = ObserveNotification["params"]["event"];
type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue =>
  v !== null && typeof v === "object" && !Array.isArray(v);
// Copy containers without consuming or transferring host-owned body streams.
function cloneEvent<T>(value: T): T {
  if (value instanceof ReadableStream) return value;
  if (Array.isArray(value)) return value.map(cloneEvent) as T;
  if (object(value))
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, cloneEvent(v)]),
    ) as T;
  return value;
}
function metadata(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(metadata);
  if (!object(value)) return value;
  if (value.body instanceof ReadableStream) {
    const { body: _, ...rest } = value;
    return { ...(metadata(rest) as ObjectValue), selection: "metadata" };
  }
  return Object.fromEntries(
    Object.entries(value).map(([k, v]) => [k, metadata(v)]),
  );
}
const base = "https://agenthooksprotocol.org/schemas/draft/";
let registry: Ajv2020 | undefined;
function validator() {
  if (!registry) {
    registry = new Ajv2020({
      strict: false,
      allErrors: true,
      ownProperties: true,
    });
    registry.addFormat("uri", fullFormats.uri);
    registry.addFormat("email", fullFormats.email);
    registry.addFormat("date-time", fullFormats["date-time"]);
    for (const schema of schemas) registry.addSchema(schema);
  }
  return registry;
}
function equal(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a instanceof ReadableStream || b instanceof ReadableStream) return false;
  if (Array.isArray(a) && Array.isArray(b))
    return a.length === b.length && a.every((v, i) => equal(v, b[i]));
  return (
    object(a) &&
    object(b) &&
    Object.keys(a).length === Object.keys(b).length &&
    Object.keys(a).every((k) => Object.hasOwn(b, k) && equal(a[k], b[k]))
  );
}

// Canonical catalogue payload locations (not synthetic input/output slots).
const targets: Record<string, Record<string, string[]>> = {
  "tool.before": { input: ["tool", "input"] },
  "tool.permission.request": { input: ["tool", "input"] },
  "tool.after": { output: ["items"] },
  "turn.start": { prompt: ["items"] },
  "turn.finish.before": { response: ["items"] },
  "model.request.before": { request: ["params"] },
  "model.response.after": { response: ["items"] },
  "context.compact.before": { instructions: ["instructions"] },
  "context.compact.after": { summary: ["summary"] },
  "user.message.inbound": { prompt: ["message", "text"] },
  "user.message.outbound": { content: ["message", "payload"] },
  "user.elicitation.result": { content: ["elicitation", "result"] },
  "workspace.change.before": { workspace: ["workspace", "change"] },
};

/** Pure atomic composition. Previous effects are effective decisions, not
 * modifications to replay. No execution, authorization, resolution or upload
 * occurs here. Use composeResponseAsync for inline content/body composition. */
export function composeResponse(
  event: ClientEvent,
  previous: Effect[],
  response: InterceptResponse,
  capabilities: Capabilities,
): CompositionResult {
  return compose(event, previous, response, capabilities);
}
export interface CompositionResult {
  event: ClientEvent;
  effects: Effect[];
  state: InterceptRequest["params"]["state"];
  shortCircuit: boolean;
}
export interface CompositionOptions {
  state?: InterceptRequest["params"]["state"];
  /** Returns reusable, host-owned snapshot bytes; does not transfer a stream. */
  readContent: (body: ReadableStream<Uint8Array>) => Promise<Uint8Array>;
  /** Register locally synthesized sources before staging can fail. */
  ownContent?: (body: ReadableStream<Uint8Array>) => void;
  /** Raw request event associated by parentEventId, source, session and server. */
  elicitationRequest?: ClientEvent;
  /** Actual subscriber projection. Metadata/omit/gap views do not grant reads. */
  selectedEvent?: ClientEvent;
}
function compose(
  event: ClientEvent,
  previous: Effect[],
  response: InterceptResponse,
  capabilities: Capabilities,
  prepared?: ClientEvent,
  preflight = false,
  previousState?: InterceptRequest["params"]["state"],
): CompositionResult {
  if (!validateInterceptResponse(response).ok)
    throw new Error("Invalid intercept response");
  const ajv = validator();
  const boundary = ajv.getSchema(
    `${base}capabilities.schema.json#/$defs/${event.type}`,
  );
  if (!boundary || !boundary(capabilities))
    throw new Error("Invalid capabilities for boundary");
  const incoming = structuredClone(response.result.effects);
  const staged = cloneEvent(prepared ?? event);
  let effects = structuredClone(previous);
  for (const effect of incoming) {
    if (
      !validateEffect(effect).ok ||
      !capabilities.effects.includes(effect.type)
    )
      throw new Error("Invalid or unsupported effect");
    if (
      ![
        "deny",
        "allow",
        "ask",
        "modify",
        "return",
        "message",
        "flow",
        "inject",
      ].includes(effect.type)
    )
      throw new Error("Unknown effect");
    // Elicitation content is inside an immutable MCP result body, not the
    // descriptor. It cannot be validated or rewritten synchronously from a
    // reference/stream. Reject rather than corrupting the catalogue envelope.
    if (
      !prepared &&
      effect.type === "modify" &&
      event.type === "user.elicitation.result"
    )
      throw new Error("Body composition requires composeResponseAsync");
    if (
      (effect.type === "return" || effect.type === "deny") &&
      event.type === "user.elicitation.request"
    ) {
      const meta = (event as ObjectValue).elicitation;
      if (
        !object(meta) ||
        (meta.mode !== "form" && meta.mode !== "url") ||
        !capabilities.elicitation?.[meta.mode]
      )
        throw new Error("Unsupported elicitation mode");
    }
    if (effect.type === "return" && event.type === "user.elicitation.request") {
      const meta = (event as ObjectValue).elicitation as ObjectValue;
      if (
        !ajv.validate(
          `${base}mcp-elicitation.schema.json#/$defs/result`,
          effect.value,
        )
      )
        throw new Error("Invalid elicitation result");
      if (!object(effect.value)) throw new Error("Invalid elicitation result");
      if (
        Object.hasOwn(effect.value, "content") &&
        (meta.mode === "url" || effect.value.action !== "accept")
      )
        throw new Error("Invalid elicitation content");
      if (!prepared && meta.mode === "form" && effect.value.action === "accept")
        throw new Error("Form validation requires composeResponseAsync");
    }
    if (effect.type === "modify") {
      const operation = effect.operation;
      const advertised = capabilities.modify?.[effect.target];
      if (
        (operation !== "replace" && operation !== "merge") ||
        !targets[event.type]?.[effect.target] ||
        !object(advertised) ||
        advertised[operation] !== true
      )
        throw new Error("Unsupported modification");
      if (
        (effect.target === "input" || operation === "merge") &&
        !object(effect.value)
      )
        throw new Error("Modification requires an object");
    }
    if (effect.type === "flow") {
      if (!capabilities.flow?.operations.includes(effect.operation))
        throw new Error("Unsupported flow operation");
      if (
        effect.operation === "continue" &&
        !previous.some((e) => e.type === "flow" && e.operation === "continue")
      ) {
        const caps = capabilities.flow;
        if (
          !(
            typeof caps.remainingContinuations === "number" &&
            caps.remainingContinuations > 0
          ) ||
          (caps.maxContinuations !== undefined &&
            (caps.continuationCount ?? 0) >= caps.maxContinuations)
        )
          throw new Error("Continuation allowance exhausted");
      }
    }
    if (
      effect.type === "inject" &&
      (effect.target !== "context" ||
        effect.operation !== "append" ||
        !["now", "next_turn"].includes(effect.deliverAt) ||
        capabilities.inject?.context.append !== true ||
        !capabilities.inject.context.deliverAt.includes(effect.deliverAt))
    )
      throw new Error("Unsupported injection");
  }
  for (const effect of incoming) {
    if (prepared || effect.type !== "modify") continue;
    const path = targets[event.type]![effect.target]!;
    let container = staged as ObjectValue;
    for (const segment of path.slice(0, -1)) {
      const next = container[segment];
      if (!object(next)) throw new Error("Missing modification target");
      container = next;
    }
    const key = path[path.length - 1]!;
    const current = container[key];
    if (effect.operation === "merge") {
      if (!object(current)) throw new Error("Merge target must be an object");
      container[key] = { ...current, ...(effect.value as ObjectValue) };
    } else container[key] = structuredClone(effect.value);
  }
  const eventSchema =
    event.type === "tool.before"
      ? "tool-before"
      : event.type === "tool.after"
        ? "tool-after"
        : "catalogue-event";
  if (
    !preflight &&
    incoming.some((e) => e.type === "modify") &&
    !ajv.validate(`${base}${eventSchema}.schema.json`, metadata(staged))
  )
    throw new Error("Invalid effective event payload");
  if (!equal(event, staged)) {
    effects = effects.filter((e) => e.type !== "return" && e.type !== "allow");
    if (previousState)
      previousState = {
        ...previousState,
        candidate: null,
        permission:
          previousState.permission === "allow"
            ? "none"
            : previousState.permission,
      };
  }
  for (const effect of incoming) {
    if (effect.type === "return")
      effects = effects.filter((e) => e.type !== "return");
    effects.push(effect);
  }
  const normalized = normalizeEffects(effects, previousState);
  if (!previousState) return { event: staged, ...normalized };
  const pending = normalizeEffects(incoming, previousState);
  return {
    event: staged,
    effects: normalized.effects,
    state: pending.state,
    shortCircuit: pending.shortCircuit,
  };
}

/** Normalize explicit and local fail-closed decisions identically. */
export function normalizeEffects(
  effects: Effect[],
  previousState?: InterceptRequest["params"]["state"],
) {
  const denied =
    previousState?.permission === "deny" ||
    effects.some((e) => e.type === "deny");
  const stopped =
    previousState?.flow === "stop" ||
    effects.some((e) => e.type === "flow" && e.operation === "stop");
  const asked =
    previousState?.permission === "ask" ||
    effects.some((e) => e.type === "ask");
  if (denied || stopped) effects = effects.filter((e) => e.type !== "return");
  if (denied || asked) effects = effects.filter((e) => e.type !== "allow");
  // Stop determines the outcome; continuation instructions remain ordered
  // pending data and must not disappear merely because execution is stopped.
  const candidate = [...effects].reverse().find((e) => e.type === "return");
  const state: NonNullable<InterceptRequest["params"]["state"]> = {
    ...structuredClone(previousState),
    candidate:
      denied || stopped
        ? null
        : candidate?.type === "return"
          ? { value: structuredClone(candidate.value) }
          : structuredClone(previousState?.candidate ?? null),
    permission: denied
      ? "deny"
      : asked
        ? "ask"
        : previousState?.permission === "allow" ||
            effects.some((e) => e.type === "allow")
          ? "allow"
          : "none",
    ...(previousState?.flow !== undefined ||
    effects.some((e) => e.type === "flow")
      ? {
          flow: stopped
            ? "stop"
            : previousState?.flow === "continue" ||
                effects.some(
                  (e) => e.type === "flow" && e.operation === "continue",
                )
              ? "continue"
              : (previousState?.flow ?? "none"),
        }
      : {}),
    ...(previousState?.instructions !== undefined ||
    effects.some(
      (e) =>
        e.type === "flow" &&
        e.operation === "continue" &&
        typeof e.instruction === "string",
    )
      ? {
          instructions: [
            ...(previousState?.instructions ?? []),
            ...effects.flatMap((e) =>
              e.type === "flow" &&
              e.operation === "continue" &&
              typeof e.instruction === "string"
                ? [e.instruction]
                : [],
            ),
          ],
        }
      : {}),
    ...(previousState?.injections !== undefined ||
    effects.some((e) => e.type === "inject")
      ? {
          injections: [
            ...(previousState?.injections ?? []),
            ...effects
              .filter((e) => e.type === "inject")
              .map((e) => structuredClone(e) as JsonValue),
          ],
        }
      : {}),
  };
  return { effects, state, shortCircuit: denied || stopped };
}

/** Compose inline effect bodies into fresh local streams before the next hook.
 * Only the returned event publishes those streams; failed responses leave the
 * caller's containers and previous effective decisions unchanged.
 */
export async function composeResponseAsync(
  event: ClientEvent,
  previous: Effect[],
  response: InterceptResponse,
  capabilities: Capabilities,
  options: CompositionOptions,
): Promise<CompositionResult> {
  // Validate the complete list before reading or materializing any body. The
  // prepared-event path suppresses only body-dependent checks until staging.
  compose(event, previous, response, capabilities, event, true, options.state);
  const staged = cloneEvent(event) as ObjectValue;
  const effects = response.result.effects;
  const selectedAt = (path: string[]): unknown => {
    let value: unknown = options.selectedEvent;
    for (const key of path) value = object(value) ? value[key] : undefined;
    return value;
  };
  const selectedBody = (value: unknown): boolean =>
    object(value) &&
    value.selection === "body" &&
    value.body !== undefined &&
    value.gap === undefined;
  const ajv = validator();
  const readJson = async (item: unknown): Promise<ObjectValue> => {
    if (
      !object(item) ||
      item.mediaType !== "application/json" ||
      !(item.body instanceof ReadableStream)
    )
      throw new Error("A raw application/json body is required");
    const bytes = await options.readContent(
      item.body as ReadableStream<Uint8Array>,
    );
    const value: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    if (!object(value)) throw new Error("Expected a JSON object body");
    return value;
  };
  const merge = (
    current: unknown,
    value: unknown,
    operation: string,
  ): unknown => {
    if (operation === "replace") return cloneEvent(value);
    if (!object(current) || !object(value))
      throw new Error("Merge requires object values");
    return { ...current, ...cloneEvent(value) };
  };
  const bodyItem = (
    old: unknown,
    value: unknown,
    role: string,
  ): ObjectValue => {
    const oldItem = object(old) ? old : {};
    const {
      body: _body,
      gap: _gap,
      size: _size,
      sha256: _sha256,
      selection: _selection,
      ...rest
    } = oldItem;
    const text = typeof value === "string" ? value : JSON.stringify(value);
    const bytes = new TextEncoder().encode(text);
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    });
    try {
      options.ownContent?.(body);
    } catch (error) {
      void body.cancel().catch(() => undefined);
      throw error;
    }
    return {
      ...rest,
      ...(typeof oldItem.id === "string"
        ? {}
        : { id: crypto.randomUUID(), synthesized: true }),
      kind: typeof oldItem.kind === "string" ? oldItem.kind : "text",
      role: typeof oldItem.role === "string" ? oldItem.role : role,
      mediaType: typeof value === "string" ? "text/plain" : "application/json",
      selection: "body",
      size: bytes.byteLength,
      body,
    };
  };
  const materialize = async (
    current: unknown,
    value: unknown,
    operation: string,
    role: string,
    array: boolean,
    mayRead = true,
  ): Promise<unknown> => {
    const old = array && Array.isArray(current) ? current[0] : current;
    // Descriptor arrays remain portable metadata (not receiver-owned body refs).
    // Inline effect bodies are otherwise encoded as one logical content item.
    if (
      operation === "replace" &&
      Array.isArray(value) &&
      value.every(
        (v) =>
          object(v) &&
          (v.selection === "metadata" || v.selection === "omit") &&
          ajv.validate(`${base}content-item.schema.json`, v),
      )
    ) {
      if (!array) throw new Error("Expected one content item");
      return cloneEvent(value);
    }
    let next = value;
    if (operation === "merge") {
      if (!mayRead)
        throw new Error("Object merge requires selected body content");
      if (array && Array.isArray(current) && current.length !== 1)
        throw new Error("Object merge requires one JSON content body");
      next = merge(await readJson(old), value, operation);
    }
    // Bind authorization to semantic content, not a freshly allocated stream.
    // A byte-identical rewrite retains the original item and pending decision.
    if (
      mayRead &&
      object(old) &&
      old.body instanceof ReadableStream &&
      (!array || (Array.isArray(current) && current.length === 1))
    ) {
      const oldBytes = await options.readContent(
        old.body as ReadableStream<Uint8Array>,
      );
      const nextBytes = new TextEncoder().encode(
        typeof next === "string" ? next : JSON.stringify(next),
      );
      if (
        oldBytes.length === nextBytes.length &&
        oldBytes.every((v, i) => v === nextBytes[i])
      )
        return current;
    }
    const item = bodyItem(old, next, role);
    return array ? [item] : item;
  };
  // Elicitation validation needs the original request, not an inferred form.
  const elicitationChanged = effects.some(
    (e) =>
      (e.type === "return" && event.type === "user.elicitation.request") ||
      (e.type === "modify" && event.type === "user.elicitation.result"),
  );
  let elicitationRequest: ObjectValue | undefined;
  let elicitationResult: ObjectValue | undefined;
  if (elicitationChanged) {
    if (
      options.selectedEvent &&
      !selectedBody(
        selectedAt([
          "elicitation",
          event.type === "user.elicitation.request" ? "request" : "result",
        ]),
      )
    )
      throw new Error("Elicitation effects require selected body content");
    const requestEvent =
      event.type === "user.elicitation.request"
        ? event
        : options.elicitationRequest;
    if (!requestEvent || requestEvent.type !== "user.elicitation.request")
      throw new Error("Correlated elicitation request is required");
    const requestMeta = (requestEvent as ObjectValue).elicitation;
    const meta = staged.elicitation;
    if (!object(requestMeta) || !object(meta))
      throw new Error("Invalid elicitation metadata");
    if (
      event.type === "user.elicitation.result" &&
      (event.parentEventId !== requestEvent.id ||
        event.source !== requestEvent.source ||
        !equal(
          object(event.session) ? event.session.id : undefined,
          object(requestEvent.session) ? requestEvent.session.id : undefined,
        ) ||
        meta.server !== requestMeta.server ||
        meta.mode !== requestMeta.mode)
    )
      throw new Error("Elicitation correlation mismatch");
    if (
      (meta.mode !== "form" && meta.mode !== "url") ||
      !capabilities.elicitation?.[meta.mode]
    )
      throw new Error("Unsupported elicitation mode");
    elicitationRequest = await readJson(requestMeta.request);
    if (
      !ajv.validate(
        `${base}mcp-elicitation.schema.json#/$defs/request`,
        elicitationRequest,
      ) ||
      (elicitationRequest.mode ?? "form") !== meta.mode
    )
      throw new Error("Invalid elicitation request body");
    if (event.type === "user.elicitation.result") {
      elicitationResult = await readJson(meta.result);
      if (elicitationResult.action !== meta.action)
        throw new Error("Elicitation action mismatch");
    }
  }
  const validateAnswer = (answer: unknown) => {
    validateElicitationAnswer(
      elicitationRequest,
      answer,
      (name, value: unknown) => {
        if (name === "form-answer") {
          const pair = value as { schema: ObjectValue; value: unknown };
          // The pinned request schema restricts the vocabulary before compilation.
          // No defaults, coercion, or unknown-field stripping can change answers.
          if (!ajv.compile(pair.schema)(pair.value))
            throw new Error("Answer does not satisfy requestedSchema");
        } else if (
          !ajv.validate(
            `${base}mcp-elicitation.schema.json#/$defs/result`,
            value,
          )
        )
          throw new Error("Invalid elicitation result body");
      },
    );
  };
  if (elicitationResult) validateAnswer(elicitationResult);
  for (const effect of effects) {
    if (effect.type !== "modify") continue;
    if (event.type === "user.elicitation.result") {
      elicitationResult = {
        ...elicitationResult,
        content: merge(
          elicitationResult?.content,
          effect.value,
          effect.operation,
        ),
      };
      continue;
    }
    const path = targets[event.type]![effect.target]!;
    let container = staged;
    for (const segment of path.slice(0, -1)) {
      const child = container[segment];
      if (!object(child)) throw new Error("Missing modification target");
      container = child;
    }
    const key = path[path.length - 1]!;
    const current = container[key];
    if (
      effect.target === "request" &&
      object(effect.value) &&
      (Object.hasOwn(effect.value, "params") ||
        Object.hasOwn(effect.value, "items"))
    ) {
      // The normalized request form lets a backend replace both model-bound
      // items and provider params. A plain opaque object remains native params.
      const request = merge(
        { params: staged.params, items: staged.items },
        effect.value,
        effect.operation,
      ) as ObjectValue;
      staged.params = request.params;
      if (!Array.isArray(request.items))
        throw new Error("Normalized request requires an items array");
      if (request.items === staged.items) continue;
      const oldItems = Array.isArray(staged.items) ? staged.items : [];
      staged.items = await Promise.all(
        request.items.map(async (value, i) => {
          if (
            object(value) &&
            (value.selection === "metadata" || value.selection === "omit") &&
            ajv.validate(`${base}content-item.schema.json`, value)
          )
            return cloneEvent(value);
          const selected = selectedAt(["items"]);
          return materialize(
            oldItems[i],
            value,
            "replace",
            "user",
            false,
            !options.selectedEvent ||
              (Array.isArray(selected) && selectedBody(selected[i])),
          );
        }),
      );
    } else if (["input", "workspace", "request"].includes(effect.target)) {
      container[key] = merge(current, effect.value, effect.operation);
    } else {
      const array = !["instructions", "summary"].includes(effect.target);
      const role =
        effect.target === "prompt"
          ? "user"
          : effect.target === "instructions"
            ? "system"
            : event.type === "tool.after"
              ? "tool"
              : "assistant";
      const selected = selectedAt(path);
      const mayRead =
        !options.selectedEvent ||
        (array
          ? Array.isArray(selected) &&
            selected.length === 1 &&
            selectedBody(selected[0])
          : selectedBody(selected));
      container[key] = await materialize(
        current,
        effect.value,
        effect.operation,
        role,
        array,
        mayRead,
      );
    }
  }
  if (elicitationResult) {
    validateAnswer(elicitationResult);
    const meta = staged.elicitation as ObjectValue;
    meta.result = bodyItem(meta.result, elicitationResult, "user");
    meta.action = elicitationResult.action;
  }
  if (elicitationRequest) {
    for (const effect of effects)
      if (effect.type === "return") validateAnswer(effect.value);
  }
  return compose(
    event,
    previous,
    response,
    capabilities,
    staged as ClientEvent,
    false,
    options.state,
  );
}
