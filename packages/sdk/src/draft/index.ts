/** Canonical draft validation and synthetic, request-capability-gated runtime slices. */
import { Ajv2020 } from "ajv/dist/2020.js";
import type { ValidateFunction } from "ajv";
import { fullFormats } from "ajv-formats/dist/formats.js";
import { schemas } from "./schemas.js";
import {
  parseEffect as decodeEffect,
  parseInterceptRequest as decodeRequest,
  parseInterceptResponse as decodeResponse,
  parseCapabilities as decodeCapabilities,
  parseCapabilitiesRequest as decodeCapabilitiesRequest,
  parseCapabilitiesResponse as decodeCapabilitiesResponse,
} from "./generated.js";
import type { Effect, InterceptRequest, InterceptResponse, Capabilities, CapabilitiesRequest, CapabilitiesResponse, ParseResult } from "./generated.js";

export type { InterceptRequest, InterceptResponse, Effect, Capabilities, JsonValue } from "./generated.js";
export * as draftCodecs from "./generated.js";
export { PROTOCOL_VERSION, SCHEMA_REVISION } from "./generated.js";
export { stageResponse, decide } from "../draft-atomic.js";
export type { PendingState } from "../draft-atomic.js";

export type DraftValidationResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly errors: readonly string[] };

// Initialize canonical validation only when used; the narrow root runner does not
// pay catalogue compilation costs while starting a short-lived stdio backend.
let registry: Ajv2020 | undefined;
const base = "https://agenthooksprotocol.org/schemas/draft/";
function validator(name: string): ValidateFunction {
  if (registry === undefined) {
    // No coercion, default insertion, removal of unknown fields, or partial acceptance.
    registry = new Ajv2020({ allErrors: true, strict: false, ownProperties: true });
    registry.addFormat("uri", fullFormats.uri);
    registry.addFormat("date-time", fullFormats["date-time"]);
    for (const schema of schemas) registry.addSchema(schema);
  }
  return registry.getSchema(base + name + '.schema.json')!;
}

// JSON Schema operates on JSON, not arbitrary JS objects (NaN, undefined, cycles, etc.).
function isJson(value: unknown, ancestors = new Set<object>()): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object" || ancestors.has(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) return false;
  ancestors.add(value);
  const valid = Array.isArray(value)
    ? Object.keys(value).length === value.length && Array.from(value).every(item => isJson(item, ancestors))
    : Reflect.ownKeys(value).every(key => {
        const property = Object.getOwnPropertyDescriptor(value, key);
        return typeof key === "string" && property?.enumerable === true && "value" in property && isJson(property.value, ancestors);
      });
  ancestors.delete(value);
  return valid;
}

function validate<T>(value: unknown, canonical: ValidateFunction, decode: (value: unknown) => ParseResult<T>): DraftValidationResult<T> {
  try {
    if (!isJson(value)) return { ok: false, errors: ["Expected a finite, acyclic JSON value"] };
    if (!canonical(value)) {
      return { ok: false, errors: (canonical.errors ?? []).map(error => `${error.instancePath || "/"}: ${error.message ?? error.keyword}`) };
    }
    // Generated decoding is deliberately permissive; canonical validation above is mandatory.
    const decoded = decode(value);
    return decoded.ok
      ? { ok: true, value: decoded.value }
      : { ok: false, errors: decoded.diagnostics.map(error => `${error.path}: ${error.message}`) };
  } catch (error) {
    return { ok: false, errors: [error instanceof Error ? error.message : String(error)] };
  }
}

export function validateEffect(value: unknown): DraftValidationResult<Effect> {
  return validate(value, validator('effect'), decodeEffect);
}

export function validateCapabilities(value: unknown): DraftValidationResult<Capabilities> {
  return validate(value, validator('capabilities'), decodeCapabilities);
}
export function validateCapabilitiesRequest(value: unknown): DraftValidationResult<CapabilitiesRequest> {
  return validate(value, validator('capabilities-request'), decodeCapabilitiesRequest);
}
export function validateCapabilitiesResponse(value: unknown): DraftValidationResult<CapabilitiesResponse> {
  return validate(value, validator('capabilities-response'), decodeCapabilitiesResponse);
}

export function validateInterceptRequest(value: unknown): DraftValidationResult<InterceptRequest> {
  const result = validate(value, validator('intercept-request'), decodeRequest);
  if (result.ok && result.value.id !== result.value.params.event.id) return { ok: false, errors: ["Request id must equal event id"] };
  return result;
}

export function validateInterceptResponse(value: unknown): DraftValidationResult<InterceptResponse> {
  return validate(value, validator('intercept-response'), decodeResponse);
}

function parse<T>(text: string, validator: (value: unknown) => DraftValidationResult<T>): DraftValidationResult<T> {
  try { return validator(JSON.parse(text) as unknown); }
  catch (error) { return { ok: false, errors: [error instanceof Error ? error.message : String(error)] }; }
}

export function parseInterceptRequest(text: string): DraftValidationResult<InterceptRequest> {
  return parse(text, validateInterceptRequest);
}

export function parseInterceptResponse(text: string): DraftValidationResult<InterceptResponse> {
  return parse(text, validateInterceptResponse);
}

export { uploadContent, prepareWireContent, stageBoundary, dispatchBoundary, ContentReceiver, prepareContent, Lineage, actualTaskChange } from "../draft-runtime.js";
export type { BoundaryState, BoundaryCapabilities, BoundaryEffect, Delivery, ContentItem, ContentView } from "../draft-runtime.js";

export type {UploadConfiguration, BodyReference, NormalizedContentInput, NormalizedContentView} from "../content-upload.js";

export { dispatchObservations } from "../observation.js";
export type { ObservationSubscription, ObservationEvent, ObservationNotification } from "../observation.js";
