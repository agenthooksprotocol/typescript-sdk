import { AuthError } from "./auth-routing.js";

/** Split challenges without interpreting commas or scheme names inside quoted strings. */
export function bearerParameters(header: string | undefined): Map<string, string> {
  const result = new Map<string, string>();
  if (header === undefined || header === "") return result;
  if (header.length > 16384 || /[\r\n\0]/.test(header)) throw new AuthError("discovery_failed");
  const parts: string[] = [];
  let start = 0, quoted = false, escaped = false;
  for (let i = 0; i < header.length; i++) {
    const c = header[i];
    if (escaped) { escaped = false; continue; }
    if (quoted && c === "\\") { escaped = true; continue; }
    if (c === '"') quoted = !quoted;
    if (c === "," && !quoted) { parts.push(header.slice(start, i)); start = i + 1; }
  }
  if (quoted || escaped) throw new AuthError("discovery_failed");
  parts.push(header.slice(start));
  let bearer = false, seenBearer = false;
  const token = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
  const scheme = new RegExp(`^(${token})(?:[ \\t]+(.*))?$`);
  const parameter = new RegExp(`^(${token})[ \\t]*=[ \\t]*(?:\"((?:[^\"\\\\]|\\\\.)*)\"|(${token}))[ \\t]*$`);
  for (const part of parts) {
    let text = part.trim();
    const beginning = scheme.exec(text);
    if (beginning && !parameter.test(text)) {
      bearer = beginning[1]?.toLowerCase() === "bearer";
      if (bearer && seenBearer) throw new AuthError("discovery_failed");
      if (bearer) seenBearer = true;
      text = beginning[2] ?? "";
    }
    if (!bearer || text === "") continue;
    // RFC 7235 token68 is not an auth-param list, including padded payloads.
    if (/^[A-Za-z0-9._~+\/-]+=*$/.test(text)) continue;
    const match = parameter.exec(text);
    if (!match) throw new AuthError("discovery_failed");
    const name = match[1]!.toLowerCase();
    if (result.has(name)) throw new AuthError("discovery_failed");
    result.set(name, match[2] !== undefined ? match[2].replace(/\\(.)/g, "$1") : match[3]!);
  }
  return result;
}
