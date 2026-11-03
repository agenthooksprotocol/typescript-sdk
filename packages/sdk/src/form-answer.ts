import { fullFormats } from "ajv-formats/dist/formats.js";

/*
 * MCP restricts an elicitation's `requestedSchema` to a flat object of primitive
 * fields (mcp-elicitation.schema.json#/$defs/PrimitiveSchemaDefinition), and the
 * request is validated against that vocabulary before an answer is. This checks
 * an answer against that closed vocabulary with JSON Schema 2020-12 semantics,
 * so no schema compiler (and no run-time code generation) is needed.
 */

type Schema = Readonly<Record<string, unknown>>;
type Format = "date" | "date-time" | "email" | "uri";

function object(value: unknown): value is Schema {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function format(name: Format, value: string): boolean {
  const check = fullFormats[name] as RegExp | ((value: string) => boolean) | { validate: RegExp | ((value: string) => boolean) };
  const validate = check instanceof RegExp || typeof check === "function" ? check : check.validate;
  return validate instanceof RegExp ? validate.test(value) : validate(value);
}

function numeric(value: unknown, integer: boolean): value is number | bigint {
  if (typeof value === "bigint") return true;
  return typeof value === "number" && (integer ? Number.isInteger(value) : Number.isFinite(value));
}

function count(value: number | undefined): number | undefined {
  return typeof value === "number" ? value : undefined;
}

function field(schema: Schema, value: unknown): boolean {
  switch (schema.type) {
    case "boolean":
      return typeof value === "boolean";
    case "integer":
    case "number": {
      if (!numeric(value, schema.type === "integer")) return false;
      if (typeof schema.minimum === "number" && value < schema.minimum) return false;
      if (typeof schema.maximum === "number" && value > schema.maximum) return false;
      return true;
    }
    case "string": {
      if (typeof value !== "string") return false;
      // JSON Schema lengths count code points, not UTF-16 units.
      const length = [...value].length;
      const min = count(schema.minLength as number | undefined);
      const max = count(schema.maxLength as number | undefined);
      if (min !== undefined && length < min) return false;
      if (max !== undefined && length > max) return false;
      if (typeof schema.format === "string" && !format(schema.format as Format, value)) return false;
      if (Array.isArray(schema.enum) && !schema.enum.includes(value)) return false;
      if (Array.isArray(schema.oneOf) &&
          schema.oneOf.filter((option) => object(option) && option.const === value).length !== 1)
        return false;
      return true;
    }
    case "array": {
      if (!Array.isArray(value)) return false;
      const min = count(schema.minItems as number | undefined);
      const max = count(schema.maxItems as number | undefined);
      if (min !== undefined && value.length < min) return false;
      if (max !== undefined && value.length > max) return false;
      const items = object(schema.items) ? schema.items : {};
      return value.every((item) => {
        if (items.type === "string" && typeof item !== "string") return false;
        if (Array.isArray(items.enum) && !items.enum.includes(item)) return false;
        if (Array.isArray(items.anyOf) &&
            !items.anyOf.some((option) => object(option) && option.const === item))
          return false;
        return true;
      });
    }
    default:
      return false;
  }
}

/** Whether a form answer satisfies a pinned MCP `requestedSchema`. */
export function satisfiesRequestedSchema(schema: unknown, value: unknown): boolean {
  if (!object(schema) || schema.type !== "object" || !object(value)) return false;
  const properties = object(schema.properties) ? schema.properties : {};
  const required = Array.isArray(schema.required) ? schema.required : [];
  if (!required.every((name) => typeof name === "string" && Object.hasOwn(value, name)))
    return false;
  // The requested schema sets no additionalProperties: unlisted answers are permitted.
  return Object.entries(properties).every(([name, definition]) =>
    !Object.hasOwn(value, name) || (object(definition) && field(definition, value[name])));
}
