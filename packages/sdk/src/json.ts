import type { Ajv2020 } from "ajv/dist/2020.js";
import { schemas } from "./draft/schemas.js";
import { addCanonicalKeywords, canonicalSchema } from "./canonical-schema.js";
import {
  encodeJsonRpcMessage,
  type JsonRpcMessage,
} from "./draft/raw.js";

/** The generated encoder checks JSON shape and writes bigint as an exact integer token. */
export function stringifyJson(value: unknown): string {
  return encodeJsonRpcMessage(value as JsonRpcMessage);
}

/** Parse lossless JSON without recursive descent or recursive envelope validation. */
export function parseJson(text: string): unknown {
  type Frame =
    | { kind: "array"; value: unknown[]; state: "first" | "value" | "separator" }
    | { kind: "object"; value: Record<string, unknown>; state: "first" | "key" | "colon" | "value" | "separator"; key: string };
  const frames: Frame[] = [];
  const numberToken = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
  let cursor = 0;
  let result: unknown;
  let hasResult = false;
  const invalid = (): never => { throw new SyntaxError(`Invalid JSON at position ${cursor}`); };
  const string = (): string => {
    const start = cursor++;
    while (cursor < text.length) {
      const character = text[cursor++];
      if (character === '"') return JSON.parse(text.slice(start, cursor)) as string;
      if (character === "\\") cursor++;
    }
    return invalid();
  };
  const append = (value: unknown): void => {
    const frame = frames[frames.length - 1];
    if (!frame) {
      result = value;
      hasResult = true;
    } else {
      if (frame.kind === "array") frame.value.push(value);
      else Object.defineProperty(frame.value, frame.key, {
        value, enumerable: true, configurable: true, writable: true,
      });
      frame.state = "separator";
    }
  };
  for (;;) {
    while (cursor < text.length && /[ \t\r\n]/.test(text[cursor]!)) cursor++;
    const frame = frames[frames.length - 1];
    const character = text[cursor];
    if (!frame && hasResult) {
      if (cursor !== text.length) invalid();
      return result;
    }
    if (frame) {
      const closing = frame.kind === "array" ? "]" : "}";
      if (character === closing && (frame.state === "first" || frame.state === "separator")) {
        cursor++;
        frames.pop();
        continue;
      }
      if (frame.state === "separator") {
        if (character !== ",") invalid();
        cursor++;
        frame.state = frame.kind === "array" ? "value" : "key";
        continue;
      }
      if (frame.kind === "object") {
        if (frame.state === "first" || frame.state === "key") {
          if (character !== '"') invalid();
          frame.key = string();
          frame.state = "colon";
          continue;
        }
        if (frame.state === "colon") {
          if (character !== ":") invalid();
          cursor++;
          frame.state = "value";
          continue;
        }
      }
    }
    if (character === "[" || character === "{") {
      cursor++;
      const child: Frame = character === "["
        ? { kind: "array", value: [], state: "first" }
        : { kind: "object", value: {}, state: "first", key: "" };
      append(child.value);
      frames.push(child);
    } else if (character === '"') {
      append(string());
    } else if (text.startsWith("true", cursor)) {
      cursor += 4;
      append(true);
    } else if (text.startsWith("false", cursor)) {
      cursor += 5;
      append(false);
    } else if (text.startsWith("null", cursor)) {
      cursor += 4;
      append(null);
    } else {
      numberToken.lastIndex = cursor;
      const token = numberToken.exec(text)?.[0];
      if (token === undefined) invalid();
      cursor += token!.length;
      append(parseLosslessNumber(token!));
    }
  }
}

/** Decimal and exponent spellings of integers must also retain their exact value. */
function parseLosslessNumber(token: string): number | bigint {
  const parts = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token)!;
  const fraction = parts[3] ?? "";
  const digits = parts[2]! + fraction;
  const scale = Number(parts[4] ?? "0") - fraction.length;
  let integer: string | undefined;
  if (/^0+$/.test(digits)) integer = "0";
  else if (Number.isSafeInteger(scale)) {
    if (scale >= 0) {
      // Bound exponent expansion independently of nesting and wire length.
      if (digits.length + scale > 1_000_000) throw new SyntaxError("JSON integer is too large");
      integer = digits + "0".repeat(scale);
    } else {
      const end = Math.max(0, digits.length + scale);
      if (/^0*$/.test(digits.slice(end))) integer = digits.slice(0, end) || "0";
    }
  }
  if (integer !== undefined) {
    const exact = BigInt(parts[1]! + integer);
    return exact >= BigInt(Number.MIN_SAFE_INTEGER) && exact <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(exact) : exact;
  }
  const value = Number(token);
  if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
    throw new SyntaxError("JSON number cannot be represented without integer rounding");
  }
  return value;
}

/** Register the canonical schemas over the lossless numeric keywords. */
export function addCanonicalSchemas(registry: Ajv2020): void {
  addCanonicalKeywords(registry);
  for (const schema of schemas) registry.addSchema(canonicalSchema(schema) as object);
}

export { canonicalSchema };
