import { HookOperationalError } from "../errors.js";

export type HeaderSource = { valueEnv: string } | { valueRef: string };
export interface HeaderResolutionContext {
  backendId: string;
  url: string;
  purpose: "event";
  /** Carries cancellation and the enclosing operation deadline. */
  signal: AbortSignal;
}
/** Harness-owned secret lookup. Never include sources or values in diagnostics. */
export type HeaderResolver = (
  source: HeaderSource,
  context: HeaderResolutionContext,
) => string | undefined | Promise<string | undefined>;

type HeaderEntry = readonly [string, string | HeaderSource];
const reserved = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "host",
  "content-type",
  "accept",
  "content-length",
  "content-encoding",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "expect",
  "origin",
  "referer",
]);
const printable = (value: unknown): value is string =>
  typeof value === "string" && !/[^\x20-\x7e]/.test(value);
// Bound custom headers independently of the underlying HTTP adapter.
const MAX_HEADER_BYTES = 16 * 1024;
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
export function validateHeaders(input: unknown): readonly HeaderEntry[] {
  if (input === undefined) return [];
  if (!input || typeof input !== "object" || Array.isArray(input)) invalid();
  const seen = new Set<string>();
  let bytes = 0;
  return Object.entries(input).map(([name, value]): HeaderEntry => {
    const lower = name.toLowerCase();
    if (
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
      seen.has(lower) ||
      reserved.has(lower) ||
      /^(proxy-|sec-|ahp-)/.test(lower)
    )
      invalid();
    seen.add(lower);
    bytes += name.length + 4;
    if (typeof value === "string") {
      if (!printable(value)) invalid();
      bytes += value.length;
    } else {
      if (!value || typeof value !== "object" || Array.isArray(value))
        invalid();
      const keys = Object.keys(value);
      if (
        keys.length !== 1 ||
        !["valueEnv", "valueRef"].includes(keys[0]!) ||
        typeof value[keys[0]!] !== "string" ||
        value[keys[0]!].length === 0
      )
        invalid();
      if (
        keys[0] === "valueEnv" &&
        !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value.valueEnv)
      )
        invalid();
    }
    if (bytes > MAX_HEADER_BYTES) invalid();
    return [
      name,
      typeof value === "string" ? value : ({ ...value } as HeaderSource),
    ];
  });
}

export async function resolveHeaders(
  entries: readonly HeaderEntry[],
  resolver: HeaderResolver | undefined,
  context: HeaderResolutionContext,
): Promise<Headers> {
  const headers = new Headers();
  let bytes = 0;
  for (const [name, source] of entries) {
    context.signal.throwIfAborted();
    let value: unknown = source;
    if (typeof source !== "string") {
      try {
        value = resolver
          ? await resolver({ ...source }, context)
          : "valueEnv" in source
            ? process.env[source.valueEnv]
            : undefined;
      } catch {
        context.signal.throwIfAborted();
        failed();
      }
      context.signal.throwIfAborted();
      if (value === "") failed();
    }
    if (!printable(value)) failed();
    bytes += name.length + value.length + 4;
    if (bytes > MAX_HEADER_BYTES) failed();
    headers.set(name, value);
  }
  return headers;
}
