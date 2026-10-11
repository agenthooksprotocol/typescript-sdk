import { Ajv2020 } from "ajv/dist/2020.js";
import { fullFormats } from "ajv-formats/dist/formats.js";
import { addCanonicalSchemas, canonicalSchema, parseJson, stringifyJson } from "../json.js";
import { mapParts } from "./content-paths.js";
import { validateElicitationAnswer } from "../elicitation.js";
import { validateInterceptResponse } from "../draft/index.js";
import type {
  EventResponses,
  TextPart,
  CanonicalMessage,
  WorkspaceChange,
  ReturnElicitResultEffect,
  ReturnMessagesEffect,
  UserElicitationRequestEvent,
  Capabilities,
  InterceptResponse,
  InterceptRequest,
  ObserveNotification,
} from "../draft/raw.js";

import { responseForRequest } from "../draft/raw.js";

export type ContextualResponse = EventResponses[keyof EventResponses];
export type ComposedEffect = NonNullable<EventResponses[keyof EventResponses]["result"]["effects"]>[number];
type ModifyEffect = Extract<ComposedEffect, { type: "modify" }>;
type OutboundModifyEffect = Extract<NonNullable<EventResponses["user.message.outbound"]["result"]["effects"]>[number], { type: "modify" }>;

// Context selects the declared effect shapes; canonical validation checks the
// complete JSON contract, including constraints beyond the generated codec.
function decodeResponse(event: ClientEvent, raw: ContextualResponse | InterceptResponse): ContextualResponse {
  const decoded = responseForRequest(event.type, raw);
  if (!decoded.ok || !validateInterceptResponse(raw).ok)
    throw new Error("Invalid intercept response");
  return decoded.value;
}

export type ClientEvent = ObserveNotification["params"]["event"];
type ObjectValue = Record<string, unknown>;
const object = (v: unknown): v is ObjectValue =>
  v !== null && typeof v === "object" && !Array.isArray(v);
// Clone only schema-owned containers; opaque host payloads retain identity.
function cloneEvent<T>(value: T): T {
  const event = mapParts(value, (part) => object(part) ? { ...part } : part);
  if (object(value) && typeof value.type === "string") {
    for (const path of Object.values(targets[value.type] ?? {})) {
      let container = event;
      for (const key of path.slice(0, -1)) {
        if (!object(container[key])) break;
        container[key] = { ...container[key] };
        container = container[key];
      }
    }
  }
  return event as T;
}
// Incoming effects are validated JSON, not host-owned opaque event payloads.
function cloneValue<T>(value: T): T {
  if (Array.isArray(value)) return value.map(cloneValue) as T;
  if (object(value))
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, cloneValue(v)]),
    ) as T;
  return value;
}
function metadata(value: unknown): unknown {
  return mapParts(value, (part) => {
    if (!object(part) || !(part.body instanceof ReadableStream)) return part;
    const { body: _, ...rest } = part;
    return { ...rest, selection: "metadata" };
  });
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
    addCanonicalSchemas(registry);
  }
  return registry;
}
function equal(a: unknown, b: unknown, key?: string): boolean {
  if (a === b) return true;
  if (key === "native" || key === "input" || key === "params") {
    // At most compare direct object-target fields; never inspect nested native data.
    return key !== "native" && object(a) && object(b) &&
      Object.keys(a).length === Object.keys(b).length &&
      Object.keys(a).every(k => Object.hasOwn(b, k) && a[k] === b[k]);
  }
  if (a instanceof ReadableStream || b instanceof ReadableStream) return false;
  if (Array.isArray(a) && Array.isArray(b))
    return a.length === b.length && a.every((v, i) => equal(v, b[i]));
  return (
    object(a) &&
    object(b) &&
    Object.keys(a).filter(k => a[k] !== undefined).length ===
      Object.keys(b).filter(k => b[k] !== undefined).length &&
    Object.keys(a).every((k) => equal(a[k], b[k], k))
  );
}

// TEMP generic JSON targets use shallow merge, not recursive host traversal.
function modifyValue(current: unknown, value: unknown, operation: string): unknown {
  if (operation === "replace") return cloneValue(value);
  if (!object(current) || !object(value))
    throw new Error("Merge requires object values");
  return { ...current, ...cloneValue(value) };
}
function modifyList<T extends TextPart | CanonicalMessage>(
  current: T[], value: T[], operation: "replace" | "merge",
): T[] {
  return operation === "replace" ? cloneValue(value) : [...current, ...cloneValue(value)];
}
function modifyForEvent(event: ClientEvent, current: unknown, effect: ModifyEffect): unknown {
  switch (effect.target) {
    case "input":
      return modifyValue(current, effect.value, effect.operation);
    case "workspace": {
      const prior = current as WorkspaceChange;
      return effect.operation === "replace" ? cloneValue(effect.value) : { ...prior, ...cloneValue(effect.value) };
    }
    case "instructions":
    case "summary":
      return modifyList(current as TextPart[], effect.value, effect.operation);
    case "content":
      if (event.type === "user.elicitation.result")
        return modifyValue(current, effect.value, effect.operation);
      // The originating event is the authority for the overlapping content target.
      return modifyList(current as CanonicalMessage[],
        (effect as OutboundModifyEffect).value,
        effect.operation);
    default:
      return modifyList(current as CanonicalMessage[], effect.value, effect.operation);
  }
}

// Canonical catalogue payload locations (not synthetic input/output slots).
const targets: Record<string, Record<string, string[]>> = {
  "tool.before": { input: ["tool", "input"] },
  "tool.permission.request": { input: ["tool", "input"] },
  "tool.after": { output: ["items"] },
  "turn.start": { prompt: ["items"] },
  "turn.finish.before": { response: ["items"] },
  "model.request.before": { request: ["items"] },
  "model.response.after": { response: ["items"] },
  "context.compact.before": { instructions: ["instructions"] },
  "context.compact.after": { summary: ["summary"] },
  "user.message.inbound": { prompt: ["message", "messages"] },
  "user.message.outbound": { content: ["message", "messages"] },
  "user.elicitation.result": { content: ["elicitation", "result"] },
  "workspace.change.before": { workspace: ["workspace", "change"] },
};

/** Pure atomic composition. Previous effects are effective decisions, not
 * modifications to replay. No execution, authorization, resolution or upload
 * occurs here. Use composeResponseAsync for correlated elicitation validation. */
export function composeResponse(
  event: ClientEvent,
  previous: ComposedEffect[],
  response: ContextualResponse | InterceptResponse,
  capabilities: Capabilities,
): CompositionResult {
  return compose(event, previous, response, capabilities);
}
export interface CompositionResult {
  event: ClientEvent;
  effects: ComposedEffect[];
  state: InterceptRequest["params"]["state"];
  shortCircuit: boolean;
}
export interface CompositionOptions {
  state?: InterceptRequest["params"]["state"];
  /** Validate each complete temporary event before applying the next modification. */
  admitStagedEvent?: (event: ClientEvent) => void;
  /** Returns reusable, host-owned snapshot bytes; does not transfer a stream. */
  readContent: (body: ReadableStream<Uint8Array>) => Promise<Uint8Array>;
  /** Register locally synthesized sources before staging can fail. */
  ownContent?: (body: ReadableStream<Uint8Array>) => void;
  /** Resolve only existing, selected receiver refs to their immutable local owners. */
  resolveAttachment?: (part: ObjectValue) => ObjectValue;
  /** Raw request event associated by parentEventId, source, session and server. */
  elicitationRequest?: ClientEvent;
  /** Actual subscriber projection. Metadata/omit/gap views do not grant reads. */
  selectedEvent?: ClientEvent;
}
function validateEffectiveEvent(event: ClientEvent): void {
  const eventSchema = event.type === "tool.before" ? "tool-before"
    : event.type === "tool.after" ? "tool-after" : "catalogue-event";
  if (!validator().validate(`${base}${eventSchema}.schema.json`, metadata(event)))
    throw new Error("Invalid effective event payload");
}
function compose(
  event: ClientEvent,
  previous: ComposedEffect[],
  response: ContextualResponse | InterceptResponse,
  capabilities: Capabilities,
  prepared?: ClientEvent,
  preflight = false,
  previousState?: InterceptRequest["params"]["state"],
): CompositionResult {
  const decoded = decodeResponse(event, response);
  const ajv = validator();
  const boundary = ajv.getSchema(
    `${base}capabilities.schema.json#/$defs/${event.type}`,
  );
  if (!boundary || !boundary(capabilities))
    throw new Error("Invalid capabilities for boundary");
  const incoming = structuredClone(decoded.result.effects ?? []);
  const staged = cloneEvent(prepared ?? event);
  let effects = structuredClone(previous);
  for (const effect of incoming) {
    if (!capabilities.effects.includes(effect.type))
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
    // Elicitation content is serialized MCP JSON inside an inline text part.
    // Its correlated request must be validated before rewriting the envelope.
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
      const meta = event.elicitation;
      if (
        !object(meta) ||
        (meta.mode !== "form" && meta.mode !== "url") ||
        !capabilities.elicitation?.[meta.mode]
      )
        throw new Error("Unsupported elicitation mode");
    }
    if (effect.type === "return" && event.type === "user.elicitation.request") {
      // The codec selected this return variant from the originating request,
      // not from the JSON value's runtime shape.
      const answer = (effect as ReturnElicitResultEffect).value;
      const meta = (event as UserElicitationRequestEvent).elicitation;
      if (
        Object.hasOwn(answer, "content") &&
        (meta.mode === "url" || answer.action !== "accept")
      )
        throw new Error("Invalid elicitation content");
      if (!prepared && meta.mode === "form" && answer.action === "accept")
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
            (typeof caps.remainingContinuations === "number" ||
              typeof caps.remainingContinuations === "bigint") &&
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
    container[key] = modifyForEvent(event, current, effect);
    if (!preflight) validateEffectiveEvent(staged);
  }
  if (!preflight && incoming.some((e) => e.type === "modify"))
    validateEffectiveEvent(staged);
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
  effects: ComposedEffect[],
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
              .map((e) => structuredClone(e)),
          ],
        }
      : {}),
  };
  return { effects, state, shortCircuit: denied || stopped };
}

/** Compose canonical inline lists before the next hook without reading attachments.
 * Only the returned event publishes edits; failed responses leave the
 * caller's containers and previous effective decisions unchanged.
 */
export async function composeResponseAsync(
  event: ClientEvent,
  previous: ComposedEffect[],
  response: ContextualResponse | InterceptResponse,
  capabilities: Capabilities,
  options: CompositionOptions,
): Promise<CompositionResult> {
  // Validate the complete list before staging edits. The prepared-event path
  // postpones correlated elicitation checks until its inline JSON is parsed.
  compose(event, previous, response, capabilities, event, true, options.state);
  const staged = cloneEvent(event) as ObjectValue;
  const decoded = decodeResponse(event, response);
  const effects = decoded.result.effects ?? [];
  const selectedAt = (path: string[]): unknown => {
    let value: unknown = options.selectedEvent;
    for (const key of path) value = object(value) ? value[key] : undefined;
    return value;
  };
  const selectedBody = (value: unknown): boolean =>
    object(value) &&
    value.selection === "body" &&
    typeof value.text === "string" &&
    value.gap === undefined;
  const ajv = validator();
  const readJson = async (item: unknown): Promise<ObjectValue> => {
    if (
      !object(item) ||
      item.kind !== "text" ||
      item.selection !== "body" ||
      item.gap !== undefined ||
      typeof item.text !== "string"
    )
      throw new Error("An inline text body is required");
    const value: unknown = parseJson(item.text);
    if (!object(value)) throw new Error("Expected a JSON object body");
    return value;
  };
  const bodyItem = (old: unknown, value: unknown): ObjectValue => {
    const oldItem = object(old) ? old : {};
    return {
      id: typeof oldItem.id === "string" ? oldItem.id : crypto.randomUUID(),
      ...(typeof oldItem.id === "string" ? {} : { synthesized: true }),
      kind: "text",
      mediaType: "text/plain",
      selection: "body",
      text: stringifyJson(value),
      ...(oldItem.category !== undefined ? { category: oldItem.category } : {}),
    };
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
          if (!ajv.compile(canonicalSchema(pair.schema) as object)(pair.value))
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
        content: modifyValue(
          elicitationResult?.content,
          effect.value,
          effect.operation,
        ),
      };
      validateAnswer(elicitationResult);
      const meta = staged.elicitation as ObjectValue;
      meta.result = bodyItem(meta.result, elicitationResult);
      meta.action = elicitationResult.action;
      validateEffectiveEvent(staged as ClientEvent);
      options.admitStagedEvent?.(staged as ClientEvent);
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
    container[key] = modifyForEvent(event, current, effect);
    validateEffectiveEvent(staged as ClientEvent);
    options.admitStagedEvent?.(staged as ClientEvent);
  }
  if (elicitationResult) {
    validateAnswer(elicitationResult);
    const meta = staged.elicitation as ObjectValue;
    meta.result = bodyItem(meta.result, elicitationResult);
    meta.action = elicitationResult.action;
  }
  if (elicitationRequest) {
    for (const effect of effects)
      if (effect.type === "return") validateAnswer(effect.value);
  }
  // Only declared message effects carry attachment authority. Tool results and
  // extension bags are opaque JSON, even if they resemble content containers.
  if (options.resolveAttachment) {
    for (const effect of effects) {
      const messages = effect.type === "inject" ? effect.value
        : effect.type === "return" && event.type === "model.request.before"
          ? (effect as ReturnMessagesEffect).value : undefined;
      if (messages !== undefined)
        mapParts({ type: "model.request.before", items: messages }, (part) => {
          if (object(part) && part.kind === "attachment") options.resolveAttachment!(part);
          return part;
        });
    }
  }
  const resolved = options.resolveAttachment
    ? mapParts(staged, (part) => object(part) && part.kind === "attachment" ? options.resolveAttachment!(part) : part)
    : staged;
  return compose(
    event,
    previous,
    response,
    capabilities,
    resolved as ClientEvent,
    false,
    options.state,
  );
}
