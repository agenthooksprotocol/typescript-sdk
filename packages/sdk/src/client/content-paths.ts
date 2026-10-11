import type { EventType, ContentItem, AttachmentBodyPart } from "../draft/raw.js";

// Canonical schema-owned part locations. Application payloads are opaque.
const contentPaths: Partial<Record<EventType, readonly (readonly string[])[]>> = {
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
  return [...(contentPaths[type as EventType] ?? []), ...(textPaths[type as EventType] ?? [])];
}
export function isPartPath(type: string, path: readonly (string | number)[]): boolean {
  return pathsFor(type).some(pattern => pattern.length === path.length && pattern.every((key, i) =>
    key === "*" ? typeof path[i] === "number" && Number.isSafeInteger(path[i]) && Number(path[i]) >= 0 : key === path[i]));
}
// Wire leaves and the legacy host-owned stream leaf share the same schema slot.
// Neither an attachment reference nor its stream is traversed or cloned here.
type LocalPart = ContentItem | (Omit<AttachmentBodyPart, "body"> & {
  body: ReadableStream<Uint8Array>;
});
type Path = (string | number)[];
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function mapLeaf(value: unknown, path: Path, map: (part: LocalPart, path: Path) => unknown): unknown {
  if (!record(value) || (value.kind !== "text" && value.kind !== "attachment")) return value;
  // This cast is restricted to catalogue-declared leaves. It does not discover
  // content in unknown properties or authorize malformed event payloads.
  return map(value as LocalPart, path);
}
/** Copy only schema containers; never inspect native data or opaque payloads.
 * The broad callback shape is retained for existing content and hook callers.
 */
export function mapParts(event: any, map: (part: any, path: Path) => any): any {
  function walk(value: unknown, remaining: readonly string[], path: Path): unknown {
    if (value === undefined) return value;
    if (remaining.length === 0) return mapLeaf(value, path, map);
    const [key, ...tail] = remaining;
    if (key === "*") return Array.isArray(value)
      ? (value as unknown[]).map((child, i) => walk(child, tail, [...path, i])) : value;
    if (!record(value) || key === undefined || !Object.hasOwn(value, key)) return value;
    return { ...value, [key]: walk(value[key], tail, [...path, key]) };
  }
  if (!record(event)) return event;
  let result: Record<string, unknown> = { ...event };
  // Call identity is a protocol-owned record, not an opaque operation payload.
  if (record(event.call)) result.call = { ...event.call };
  if (typeof event.type !== "string") return result;
  for (const path of pathsFor(event.type)) result = walk(result, path, []) as Record<string, unknown>;
  return result;
}
export function localParts(event: any): { part: any; path: Path }[] {
  const parts: { part: any; path: Path }[] = [];
  mapParts(event, (part: LocalPart, path) => { parts.push({ part, path }); return part; });
  return parts;
}
