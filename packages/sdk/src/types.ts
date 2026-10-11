/** General JSON values, independent of protocol event and effect models.
 * bigint preserves lossless integers when used with the SDK JSON codec. */
export type JsonPrimitive = null | boolean | number | bigint | string;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export type JsonObject = { [key: string]: JsonValue };
