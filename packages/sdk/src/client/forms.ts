import type { Static, TObject, TSchema } from "@sinclair/typebox";
import { Ajv2020 } from "ajv/dist/2020.js";
import { schemas } from "../draft/schemas.js";
import type {
  McpElicitationElicitRequestFormParams,
  McpElicitationElicitResult,
  ElicitResult,
  McpElicitationPrimitiveSchemaDefinition,
} from "../draft/raw.js";
import { addCanonicalSchemas } from "../json.js";
import { contract, decodeContract, freezeContractValue, type Codec } from "./contracts.js";

/** Canonical MCP envelope, with a typed answer only when content is present.
 * Missing content validates as an empty form answer, or an explicit URL confirmation.
 */
export type FormResult<T> = Omit<ElicitResult<T>, "action" | "content"> & (
  | { action: "accept"; content: T }
  | { action: "accept"; content?: never }
  | { action: "decline" | "cancel"; content?: never }
);

export interface Form<S extends TObject> {
  readonly answer: Codec<Static<S>>;
  /** Result codec suitable for Hooks contracts.result. */
  readonly codec: Codec<FormResult<Static<S>>>;
  readonly requestedSchema: McpElicitationElicitRequestFormParams["requestedSchema"];
  request(message: string): McpElicitationElicitRequestFormParams;
  decode(result: unknown, mode?: "form" | "url"): FormResult<Static<S>>;
}

const canonical = new Ajv2020({ allErrors: true, strict: false, ownProperties: true });
const mcpId = "https://agenthooksprotocol.org/schemas/draft/mcp-elicitation.schema.json";
const mcpSchema = schemas.find((schema) => schema.$id === mcpId);
if (!mcpSchema) throw new Error("Missing canonical MCP elicitation schema");
addCanonicalSchemas(canonical);
const validateRequest = canonical.compile({ $ref: `${mcpId}#/$defs/ElicitRequestFormParams` });
const validateResult = canonical.compile({ $ref: `${mcpId}#/$defs/ElicitResult` });
const metadata = ["title", "description", "default"];

function keywords(schema: TSchema, allowed: string[], path: string): void {
  for (const key of Object.keys(schema)) {
    if (!allowed.includes(key)) throw new Error(`Unsupported form keyword ${path}.${key}`);
  }
}

function enumeration(schema: TSchema, path: string): string[] {
  if (schema.anyOf !== undefined) {
    keywords(schema, ["anyOf", ...metadata], path);
    if (!Array.isArray(schema.anyOf) || schema.anyOf.length === 0) {
      throw new Error(`Expected string enum at ${path}`);
    }
    return schema.anyOf.flatMap((option: TSchema, index: number) => {
      keywords(option, ["type", "const"], `${path}.anyOf[${index}]`);
      if (option.type !== "string" || typeof option.const !== "string") {
        throw new Error(`Expected string literal at ${path}.anyOf[${index}]`);
      }
      return [option.const];
    });
  }
  keywords(schema, ["type", "const", ...metadata], path);
  if (schema.type !== "string" || typeof schema.const !== "string") {
    throw new Error(`Expected string enum at ${path}`);
  }
  return [schema.const];
}

function primitive(schema: TSchema, path: string): McpElicitationPrimitiveSchemaDefinition {
  const annotations = Object.fromEntries(metadata.filter((key) => Object.hasOwn(schema, key)).map((key) => [key, schema[key]]));
  if (schema.anyOf !== undefined || schema.const !== undefined) {
    return { type: "string", enum: enumeration(schema, path), ...annotations };
  }
  if (schema.type === "array") {
    keywords(schema, ["type", "items", "minItems", "maxItems", ...metadata], path);
    if (!schema.items || typeof schema.items !== "object" || Array.isArray(schema.items)) {
      throw new Error(`Expected string enum items at ${path}`);
    }
    // Item annotations cannot be represented by an untitled MCP multi-select.
    keywords(schema.items, ["anyOf", "type", "const"], `${path}.items`);
    return { ...Object.fromEntries(Object.entries(schema)), ...annotations, type: "array", items: { type: "string", enum: enumeration(schema.items, `${path}.items`) } };
  }
  if (schema.type === "string") {
    keywords(schema, ["type", "minLength", "maxLength", "format", ...metadata], path);
    if (schema.format !== undefined && !["date", "date-time", "email", "uri"].includes(schema.format)) {
      throw new Error(`Unsupported form format at ${path}: ${schema.format}`);
    }
    return { ...Object.fromEntries(Object.entries(schema)), type: "string" };
  }
  if (schema.type === "number" || schema.type === "integer") {
    keywords(schema, ["type", "minimum", "maximum", ...metadata], path);
    return { ...Object.fromEntries(Object.entries(schema)), type: schema.type };
  }
  if (schema.type === "boolean") {
    keywords(schema, ["type", ...metadata], path);
    return { ...Object.fromEntries(Object.entries(schema)), type: "boolean" };
  }
  throw new Error(`Unsupported form schema at ${path}`);
}

/** Declare the answer once. Only losslessly representable MCP form fields are supported.
 * Root keywords are restricted to type, properties and required; nested objects,
 * pattern, exclusive limits, arbitrary arrays and custom formats are rejected.
 */
export function form<S extends TObject>(schema: S, validate?: (value: Static<S>) => void): Form<S> {
  keywords(schema, ["type", "properties", "required"], "$");
  if (schema.type !== "object" || !schema.properties || typeof schema.properties !== "object") {
    throw new Error("A form requires a TypeBox object schema");
  }
  const properties: Record<string, McpElicitationPrimitiveSchemaDefinition> = Object.fromEntries(
    Object.entries(schema.properties).map(([name, property]) => [name, primitive(property, `$.${name}`)]),
  );
  const requestedSchema: McpElicitationElicitRequestFormParams["requestedSchema"] = {
    type: "object", properties,
    ...(schema.required === undefined ? {} : { required: [...schema.required] }),
  };
  if (!validateRequest({ message: "", mode: "form", requestedSchema })) {
    throw new Error(`Invalid MCP form schema: ${canonical.errorsText(validateRequest.errors)}`);
  }
  // Keep the declaration and derived advertisement correlated without freezing
  // or mutating the caller's TypeBox schema (defaults may contain arrays).
  const advertisement = freezeContractValue(structuredClone(requestedSchema));
  const answer = contract(schema, validate);
  const decode = (value: unknown, mode: "form" | "url" = "form"): FormResult<Static<S>> => {
    if (!validateResult(value)) throw new Error(`Invalid MCP elicitation result: ${canonical.errorsText(validateResult.errors)}`);
    const result = value as McpElicitationElicitResult;
    if (Object.hasOwn(result, "content") && (mode === "url" || result.action !== "accept")) {
      throw new Error("Only accepted form results can contain content");
    }
    if (mode === "form" && result.action === "accept") {
      // Validate absent content without inserting it into the wire envelope.
      decodeContract(answer, result.content ?? {});
    }
    return result as FormResult<Static<S>>;
  };
  const codec: Codec<FormResult<Static<S>>> = { decode: (value) => decode(value, "form"), encode: (value) => decode(value, "form") };
  return {
    answer, codec, requestedSchema: advertisement,
    request: (message) => {
      const request: McpElicitationElicitRequestFormParams = { mode: "form", message, requestedSchema: advertisement };
      if (!validateRequest(request)) throw new Error("Invalid MCP form request");
      return request;
    },
    decode: (value, mode = "form") => decodeContract(
      mode === "form" ? codec : { decode: (wire) => decode(wire, "url"), encode: (wire) => decode(wire, "url") },
      value,
    ),
  };
}
