import { Ajv2020 } from 'ajv/dist/2020.js';
import { fullFormats } from 'ajv-formats/dist/formats.js';
import type { Static, TSchema } from '@sinclair/typebox';
import { assertJsonValue } from '../validation.js';
import type { BoundaryResult, EventInput } from './types.js';
import type { Event, Candidate, InterceptRequest, ToolBeforeEvent } from '../draft/raw.js';
import type { ComposedEffect } from './composition.js';

/** A caller-owned codec. Decode and encode must preserve all JSON data. */
export interface Codec<T> {
  decode(value: unknown): T;
  encode(value: T): unknown;
}

/** One runtime schema infers T and performs non-coercing declared validation.
 * An optional invariant runs on every complete staged value, never on patches. */
export function contract<S extends TSchema>(schema: S, invariant?: (value: Static<S>) => void): Codec<Static<S>> {
  const ajv = new Ajv2020({ strict: true, allErrors: true, ownProperties: true });
  for (const [name, format] of Object.entries(fullFormats)) ajv.addFormat(name, format);
  const validate = ajv.compile(JSON.parse(JSON.stringify(schema)));
  return {
    decode(value) {
      assertJsonValue(value);
      if (!validate(value)) throw new Error('Value violates declared contract');
      const decoded = structuredClone(value) as Static<S>;
      invariant?.(decoded);
      if (!sameJson(value, decoded)) throw new Error("Contract invariants must not alter JSON data");
      return decoded;
    },
    encode(value) { return value; },
  };
}

function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) &&
    a.length === b.length && a.every((value, index) => sameJson(value, b[index]));
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  const left = a as Record<string, unknown>, right = b as Record<string, unknown>;
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length && keys.every(key => Object.hasOwn(right, key) && sameJson(left[key], right[key]));
}

/** Admission includes a lossless round-trip check, so stripping codecs cannot
 * silently discard forward-compatible opaque fields. Caller code sees a copy. */
export function decodeContract<T>(codec: Codec<T>, value: unknown): T {
  assertJsonValue(value);
  const original = structuredClone(value);
  const decoded = codec.decode(structuredClone(value));
  const encoded = codec.encode(decoded);
  assertJsonValue(encoded);
  if (!sameJson(original, encoded)) throw new Error('Declared codec must preserve all JSON data');
  return decoded;
}

/** @internal Encode host values without allowing a JSON-shaped input to lose extras. */
export function encodeContract<T>(codec: Codec<T>, value: T): unknown {
  let jsonInput = false;
  try { assertJsonValue(value); jsonInput = true; } catch { /* Non-JSON caller types use their codec representation. */ }
  const original = jsonInput ? structuredClone(value) : value;
  const encoded = codec.encode(jsonInput ? structuredClone(value) : value);
  decodeContract(codec, encoded);
  if (jsonInput && !sameJson(original, encoded)) throw new Error("Declared codec must preserve all JSON data");
  return encoded;
}

/** @internal Keep decoded JSON candidate snapshots as immutable as wire snapshots. */
export function freezeContractValue<T>(value: T, seen = new WeakSet<object>()): T {
  if (value !== null && typeof value === "object" && !seen.has(value)) {
    seen.add(value);
    for (const child of Object.values(value)) freezeContractValue(child, seen);
    Object.freeze(value);
  }
  return value;
}

/** Explicit caller selection for opaque host facts. No selection or codec means
 * no shape interpretation. These bindings validate; they never patch wire data. */
export interface PayloadContract<T = unknown> {
  /** Explicit schema-owned container keys ending at the opaque host slot. */
  path: readonly string[];
  codec: Codec<T>;
}
export interface BoundaryContracts<Arguments = unknown, Result = unknown, P = unknown> {
  arguments?: Codec<Arguments>;
  result?: Codec<Result>;
  provenance?: Codec<P>;
  /** Provider params, task change/prior, native permission rules, discovery and
   * native data can each use a caller-selected binding without SDK shape guesses. */
  payloads?: readonly PayloadContract<unknown>[];
}

export type ToolBeforeInput<Arguments = unknown> = Omit<EventInput<'tool.before'>, 'input'> & { input: Arguments };
export type ToolBeforeResult<Arguments = unknown, Result = unknown, P = unknown> = Omit<BoundaryResult<'tool.before'>, 'input' | 'event' | 'state'> & {
  readonly input: Arguments;
  event: Omit<BoundaryResult<'tool.before'>['event'], 'tool'> & {
    tool: Omit<BoundaryResult<'tool.before'>['event']['tool'], 'input'> & { input: Arguments };
  };
  readonly state: Omit<BoundaryResult<'tool.before'>['state'], 'candidate'> & {
    readonly candidate: null | Readonly<Pick<Candidate<Result, P>, "value" | "provenance">>;
  };
};

/** @internal Validate only declared opaque slots, before atomic publication. */
export function admitContracts(contracts: BoundaryContracts | undefined, event: Event, state: InterceptRequest["params"]["state"], effects: readonly ComposedEffect[] = []): void {
  if (!contracts) return;
  if (contracts.arguments && event.type === 'tool.before') decodeContract(contracts.arguments, (event as ToolBeforeEvent).tool.input);
  for (const binding of contracts.payloads ?? []) {
    let value: unknown = event;
    for (const key of binding.path) {
      if (value === null || typeof value !== "object" || !Object.hasOwn(value, key)) { value = undefined; break; }
      value = (value as Record<string, unknown>)[key];
    }
    decodeContract(binding.codec, value);
  }
  if (contracts.result) {
    for (const effect of effects) if (effect.type === 'return') decodeContract(contracts.result, effect.value);
    if (state?.candidate !== undefined && state.candidate !== null) decodeContract(contracts.result, state.candidate.value);
  }
  if (contracts.provenance && state?.candidate?.provenance !== undefined) decodeContract(contracts.provenance, state.candidate.provenance);
}
