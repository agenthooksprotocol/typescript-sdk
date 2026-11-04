import { _, type Ajv2020, type KeywordCxt } from "ajv/dist/2020.js";

/**
 * Validate integers natively instead of projecting bigint to Number. Projection can
 * silently round bounds, or change negative values and opaque extension payloads.
 * All other canonical keywords remain intact; numeric constraints retain exact
 * bigint comparisons. The raw object is never modified.
 *
 * The keywords emit code rather than calling closures, so the same definitions
 * serve runtime registries and the precompiled validators.
 */
export function addCanonicalKeywords(registry: Ajv2020): void {
  registry.addKeyword({
    keyword: "losslessType",
    schemaType: ["string", "array"],
    code(cxt: KeywordCxt) {
      const { data } = cxt;
      const types: string[] = Array.isArray(cxt.schema) ? cxt.schema : [cxt.schema];
      const checks = types.map((type) => {
        switch (type) {
          case "integer":
            return _`(typeof ${data} == "bigint" || (typeof ${data} == "number" && Number.isInteger(${data})))`;
          case "number":
            return _`(typeof ${data} == "bigint" || (typeof ${data} == "number" && Number.isFinite(${data})))`;
          case "null": return _`${data} === null`;
          case "array": return _`Array.isArray(${data})`;
          case "object":
            return _`(${data} !== null && typeof ${data} == "object" && !Array.isArray(${data}))`;
          default: return _`typeof ${data} == ${type}`;
        }
      });
      cxt.fail(_`!(${checks.reduce((all, check) => _`${all} || ${check}`)})`);
    },
  });
  const comparisons = {
    minimum: ">=",
    maximum: "<=",
    exclusiveMinimum: ">",
    exclusiveMaximum: "<",
  } as const;
  for (const [keyword, operator] of Object.entries(comparisons)) {
    registry.addKeyword({
      keyword: `lossless_${keyword}`,
      schemaType: "number",
      code(cxt: KeywordCxt) {
        const { data } = cxt;
        // Mixed bigint/number comparison is exact in JavaScript.
        const bound = cxt.schema as number;
        const holds = operator === ">=" ? _`${data} >= ${bound}`
          : operator === "<=" ? _`${data} <= ${bound}`
          : operator === ">" ? _`${data} > ${bound}`
          : _`${data} < ${bound}`;
        cxt.fail(_`typeof ${data} == "bigint" && !(${holds})`);
      },
    });
  }
  registry.addKeyword({
    keyword: "lossless_multipleOf",
    schemaType: "number",
    code(cxt: KeywordCxt) {
      const { data } = cxt;
      // A finite decimal divisor p/q divides an integer iff integer*q % p is zero.
      const [mantissa, exponent = "0"] = (cxt.schema as number).toString().split("e");
      const [whole, fraction = ""] = mantissa!.split(".");
      const coefficient = (BigInt(whole! + fraction)).toString();
      const scale = fraction.length - Number(exponent);
      const divides = scale >= 0
        ? _`(${data} * BigInt(${"1" + "0".repeat(scale)})) % BigInt(${coefficient}) === BigInt(0)`
        : _`${data} % (BigInt(${coefficient}) * BigInt(${"1" + "0".repeat(-scale)})) === BigInt(0)`;
      cxt.fail(_`typeof ${data} == "bigint" && !(${divides})`);
    },
  });
}

/** Rewrite numeric keywords to their lossless forms; instance values are kept. */
export function canonicalSchema(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalSchema);
  if (value === null || typeof value !== "object") return value;
  const result: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (key === "type" && (child === "integer" || child === "number" ||
        (Array.isArray(child) && (child.includes("integer") || child.includes("number"))))) {
      result.losslessType = child;
    } else {
      // These keywords contain instance values, not child schemas.
      result[key] = ["const", "enum", "default", "examples"].includes(key)
        ? child
        : canonicalSchema(child);
      if (["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"].includes(key) && typeof child === "number") {
        result[`lossless_${key}`] = child;
      }
    }
  }
  return result;
}
