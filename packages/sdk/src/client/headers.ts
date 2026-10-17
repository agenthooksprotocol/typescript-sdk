import { validateHeaderName, validateHeaderValue } from "node:http";
import { HookOperationalError } from "../errors.js";
import { auth, type AuthContext, type AuthProvider } from "./auth.js";

type HeaderSource = { valueEnv: string } | { valueRef: string };
type HeaderEntry = readonly [string, string | HeaderSource];
export type HeaderSecrets = Partial<
  Pick<
    AuthProvider,
    "resolveEnvironmentVariable" | "resolveCredentialReference"
  >
>;

function invalid(): never {
  throw new HookOperationalError(
    "INVALID_CONFIG",
    "Invalid HTTP registration headers",
  );
}
function failed(): never {
  throw new HookOperationalError(
    "IO_ERROR",
    "HTTP registration header resolution failed",
  );
}
function validate(name: string, value: string): void {
  validateHeaderName(name);
  validateHeaderValue(name, value);
  new Headers({ [name]: value });
}
export function validateHeaders(input: unknown): readonly HeaderEntry[] {
  if (input === undefined) return [];
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid();
  const entries = new Map<string, HeaderEntry>();
  for (const [name, value] of Object.entries(input)) {
    try {
      validate(name, typeof value === "string" ? value : "");
    } catch {
      invalid();
    }
    let source: string | HeaderSource;
    if (typeof value === "string") source = value;
    else {
      if (!value || typeof value !== "object" || Array.isArray(value))
        invalid();
      const keys = Object.keys(value).filter(
        (key) => key === "valueEnv" || key === "valueRef",
      );
      if (
        keys.length !== 1 ||
        typeof value[keys[0]!] !== "string" ||
        value[keys[0]!].length === 0
      )
        invalid();
      if (
        keys[0] === "valueEnv" &&
        !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value.valueEnv)
      )
        invalid();
      source =
        keys[0] === "valueEnv"
          ? { valueEnv: value.valueEnv }
          : { valueRef: value.valueRef };
    }
    // Configuration iteration order is authoritative, including casing aliases.
    entries.set(name.toLowerCase(), [name, source]);
  }
  return [...entries.values()];
}
export async function resolveHeaders(
  entries: readonly HeaderEntry[],
  secrets: HeaderSecrets | undefined,
  context: AuthContext & { signal: AbortSignal },
): Promise<Headers> {
  const headers = new Headers();
  for (const [name, source] of entries) {
    context.signal.throwIfAborted();
    let value: unknown = source;
    try {
      if (typeof source !== "string") {
        value =
          "valueEnv" in source
            ? await (
                secrets?.resolveEnvironmentVariable ??
                auth.resolveEnvironmentVariable
              ).call(secrets ?? auth, source.valueEnv, context)
            : await (
                secrets?.resolveCredentialReference ??
                auth.resolveCredentialReference
              ).call(secrets ?? auth, source.valueRef, context);
        if (value === "") failed();
      }
      context.signal.throwIfAborted();
      if (typeof value !== "string") failed();
      validate(name, value);
      headers.set(name, value);
    } catch {
      context.signal.throwIfAborted();
      failed();
    }
  }
  return headers;
}
