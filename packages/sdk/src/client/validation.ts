import { events, type EventType } from "../draft/raw.js";

/** Admit an external event name against the generated catalogue. Unknown names
 * remain raw evidence, not authority for a contextual response. */
export function isEventType(value: unknown): value is EventType {
  return Object.values(events).some(event =>
    typeof event === "string" && !event.includes("*") && event === value);
}

import { schemaValidator } from "../schema-validators.js";

/** Validate against the checked-in canonical schema without coercion. */
export function validateWire(name: string, value: unknown, fragment = ""): string[] {
  const validate = schemaValidator(
    `https://agenthooksprotocol.org/schemas/draft/${name}.schema.json${fragment === "" ? "" : `#${fragment}`}`,
  );
  if (!validate) return ["Unknown protocol schema"];
  if (validate(value)) return [];
  return (validate.errors ?? []).map((e) => `${e.instancePath}: ${e.keyword}`);
}
