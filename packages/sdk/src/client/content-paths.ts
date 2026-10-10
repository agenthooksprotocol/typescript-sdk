import type { EventType } from "../draft/generated.js";

// Canonical schema-owned part locations. Application payloads are opaque.
const contentPaths: Record<string, readonly (readonly string[])[]> = {
  "config.change.after": [["items", "*"]],
  "config.change.before": [["items", "*"]],
  "context.compact.after": [["items", "*", "parts", "*"]],
  "context.compact.before": [["items", "*", "parts", "*"]],
  "file.changed": [
    ["changes", "*", "after"],
    ["changes", "*", "before"],
    ["items", "*"],
  ],
  "hook.failure": [["items", "*"]],
  "model.error": [["items", "*"]],
  "model.request.before": [["items", "*", "parts", "*"]],
  "model.response.after": [["items", "*", "parts", "*"]],
  "model.switch.after": [["items", "*"]],
  "model.switch.before": [["items", "*"]],
  "session.end": [["items", "*"]],
  "session.start": [["items", "*", "parts", "*"]],
  "task.change.after": [["items", "*"]],
  "task.change.before": [["items", "*"]],
  "tool.after": [
    ["fileChanges", "*", "after"],
    ["fileChanges", "*", "before"],
    ["items", "*", "parts", "*"],
  ],
  "tool.batch.after": [["items", "*"]],
  "tool.before": [["items", "*"]],
  "tool.permission.request": [["items", "*"]],
  "tool.permission.resolved": [["items", "*"]],
  "tool.progress": [
    ["items", "*"],
    ["partialOutput", "parts", "*"],
  ],
  "turn.end": [["items", "*", "parts", "*"]],
  "turn.finish.before": [["items", "*", "parts", "*"]],
  "turn.progress": [
    ["delta", "parts", "*"],
    ["items", "*"],
  ],
  "turn.start": [["items", "*", "parts", "*"]],
  "user.attention": [["items", "*"]],
  "user.elicitation.request": [["items", "*"]],
  "user.elicitation.result": [["items", "*"]],
  "user.message.inbound": [
    ["items", "*"],
    ["message", "messages", "*", "parts", "*"],
  ],
  "user.message.outbound": [
    ["items", "*"],
    ["message", "messages", "*", "parts", "*"],
  ],
  "workspace.change.after": [["items", "*"]],
  "workspace.change.before": [["items", "*"]],
};

const textPaths: Partial<Record<EventType, readonly (readonly string[])[]>> = {
  "context.compact.before": [["instructions", "*"]],
  "context.compact.after": [["summary", "*"]],
  "user.attention": [["attention", "title", "*"], ["attention", "message", "*"]],
  "user.elicitation.request": [["elicitation", "request"]],
  "user.elicitation.result": [["elicitation", "result"]],
};
export function pathsFor(type: string): readonly (readonly string[])[] {
  return [...(contentPaths[type] ?? []), ...(textPaths[type as EventType] ?? [])];
}
export function isPartPath(type: string, path: readonly (string | number)[]): boolean {
  return pathsFor(type).some(pattern => pattern.length === path.length && pattern.every((key, i) =>
    key === "*" ? typeof path[i] === "number" && Number.isSafeInteger(path[i]) && Number(path[i]) >= 0 : key === path[i]));
}
/** Copy only schema containers; never inspect native data or opaque payloads. */
export function mapParts(event: any, map: (part: any, path: (string | number)[]) => any): any {
  function walk(value: any, remaining: readonly string[], path: (string | number)[]): any {
    if (value === undefined) return value;
    if (remaining.length === 0) return map(value, path);
    const [key, ...tail] = remaining;
    if (key === "*") return Array.isArray(value) ? value.map((child, i) => walk(child, tail, [...path, i])) : value;
    if (value === null || typeof value !== "object" || !Object.hasOwn(value, key!)) return value;
    return { ...value, [key!]: walk(value[key!], tail, [...path, key!]) };
  }
  let result = { ...event };
  // Call identity is a protocol-owned record, not an opaque operation payload.
  if (event?.call !== null && typeof event?.call === "object") result.call = { ...event.call };
  for (const path of pathsFor(event?.type)) result = walk(result, path, []);
  return result;
}
export function localParts(event: any): { part: any; path: (string | number)[] }[] {
  const parts: { part: any; path: (string | number)[] }[] = [];
  mapParts(event, (part, path) => { parts.push({ part, path }); return part; });
  return parts;
}
