import { validators } from "./draft/validators/index.js";

/** One validation error, in the shape the precompiled validators report. */
export interface SchemaError {
  readonly instancePath: string;
  readonly keyword: string;
  readonly message?: string;
}

/** A precompiled canonical validator: no code is generated at run time. */
export type SchemaValidator = ((value: unknown) => boolean) & {
  errors?: readonly SchemaError[] | null;
};

const table = validators as unknown as Readonly<Record<string, SchemaValidator>>;

/** The validator for a canonical schema URI, optionally `#/$defs/<name>`. */
export function schemaValidator(uri: string): SchemaValidator | undefined {
  return Object.hasOwn(table, uri) ? table[uri] : undefined;
}

/** Validate against a canonical schema URI; false when no such schema exists. */
export function validateSchema(uri: string, value: unknown): boolean {
  return schemaValidator(uri)?.(value) === true;
}

/** Render errors as Ajv's `errorsText` does. */
export function errorsText(errors: readonly SchemaError[] | null | undefined): string {
  if (!errors?.length) return "No errors";
  return errors.map((error) => `data${error.instancePath} ${error.message ?? error.keyword}`).join(", ");
}
