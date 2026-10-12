import { events, type EventType } from "../draft/raw.js";

/** Admit an external event name against the generated catalogue. Unknown names
 * remain raw evidence, not authority for a contextual response. */
export function isEventType(value: unknown): value is EventType {
  return Object.values(events).some(event => event === value);
}

import { Ajv2020 } from "ajv/dist/2020.js";
import { fullFormats } from "ajv-formats/dist/formats.js";
import { addCanonicalSchemas } from "../json.js";

let registry: Ajv2020 | undefined;
/** Validate against the checked-in canonical schema without coercion. */
export function validateWire(name: string, value: unknown): string[] {
  if (!registry) {
    registry = new Ajv2020({
      allErrors: true,
      strict: false,
      ownProperties: true,
    });
    registry.addFormat("uri", fullFormats.uri);
    registry.addFormat("date-time", fullFormats["date-time"]);
    addCanonicalSchemas(registry);
  }
  const validate = registry.getSchema(
    `https://agenthooksprotocol.org/schemas/draft/${name}.schema.json`,
  );
  if (!validate) return ["Unknown protocol schema"];
  if (validate(value)) return [];
  return (validate.errors ?? []).map((e) => `${e.instancePath}: ${e.keyword}`);
}
