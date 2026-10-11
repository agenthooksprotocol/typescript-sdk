import { parseJson as parseLosslessJson } from "./json.js";
import { HookOperationalError } from "./errors.js";
import type { JsonObject, JsonValue } from "./types.js";

// JSON admission is shared by caller codecs, not a protocol compatibility parser.
export function assertJsonValue(
  value: unknown,
  label = "value",
): asserts value is JsonValue {
  assertJsonValueInner(value, label, new WeakSet<object>());
}

export function assertJsonObject(
  value: unknown,
  label = "value",
): asserts value is JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HookOperationalError(
      "MALFORMED_JSON_RPC",
      `${label} must be a JSON object`,
    );
  }
  assertJsonValue(value, label);
}

function assertJsonValueInner(
  value: unknown,
  label: string,
  seen: WeakSet<object>,
): void {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return;
  if (typeof value === "bigint") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value !== "object")
    throw new HookOperationalError(
      "MALFORMED_JSON_RPC",
      `${label} is not a JSON value`,
    );
  if (seen.has(value))
    throw new HookOperationalError(
      "MALFORMED_JSON_RPC",
      `${label} contains a cycle`,
    );
  seen.add(value);
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value).filter((key) => key !== "length");
    if (
      keys.length !== value.length ||
      keys.some((key, index) => key !== String(index))
    ) {
      throw new HookOperationalError(
        "MALFORMED_JSON_RPC",
        `${label} must be a dense JSON array`,
      );
    }
    for (let index = 0; index < value.length; index += 1)
      assertJsonValueInner(value[index], `${label}[${index}]`, seen);
  } else {
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null)
      throw new HookOperationalError(
        "MALFORMED_JSON_RPC",
        `${label} must be a plain JSON object`,
      );
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string")
        throw new HookOperationalError(
          "MALFORMED_JSON_RPC",
          `${label} cannot have symbol keys`,
        );
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !descriptor.enumerable ||
        !("value" in descriptor)
      ) {
        throw new HookOperationalError(
          "MALFORMED_JSON_RPC",
          `${label}.${key} must be an enumerable data property`,
        );
      }
      assertJsonValueInner(descriptor.value, `${label}.${key}`, seen);
    }
  }
  seen.delete(value);
}

export function parseJson(line: string): unknown {
  try {
    return parseLosslessJson(line);
  } catch (error) {
    throw new HookOperationalError(
      "MALFORMED_JSON",
      "Message is not valid JSON",
      { cause: error },
    );
  }
}
