/** RFC 6749 section 3.3 scope list: 1*NQCHAR tokens separated by exactly one SP. */
const SCOPE_LIST = /^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/;

/** True for a token-response `scope` that is treated as omitted: absent, JSON null,
 * or a string of only SP, HTAB, CR and LF (servers send `""` for "nothing to report"). */
export function omittedScope(value: unknown): value is undefined | null | string {
  return value === undefined || value === null || (typeof value === "string" && /^[ \t\r\n]*$/.test(value));
}

/**
 * Parse a token-response `scope`: `undefined` when omitted (inherit the requested
 * set or the previous grant), the scope tokens when it is a valid scope list, and
 * `null` when it is malformed (any other string or JSON type).
 */
export function responseScopes(value: unknown): string[] | undefined | null {
  if (omittedScope(value)) return undefined;
  return typeof value === "string" && SCOPE_LIST.test(value) ? value.split(" ") : null;
}
