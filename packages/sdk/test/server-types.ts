import {
  hooks,
  attachments,
  type ServerHandlers,
  type ServerReply,
  type InterceptContext,
} from "agenthooksprotocol/server";
import { serveStdio, type StdioOptions } from "agenthooksprotocol/server/stdio";
import type { Readable, Writable } from "node:stream";
declare const request: Request;
declare const user: { id: string };
declare const policyService: {
  handle(context: InterceptContext<"tool.before">, user: { id: string }): Promise<ServerReply<"tool.before">>;
};
const handlers = {
  intercept: {
    toolBefore(ctx) {
      const eventType: "tool.before" = ctx.event.type;
      const toolName: string = ctx.event.tool.name;
      const signal: AbortSignal = ctx.signal;
      void eventType;
      void toolName;
      void signal;
      return policyService.handle(ctx, user);
    },
  },
  observe: {
    sessionEnd(ctx) {
      const eventType: "session.end" = ctx.event.type;
      void eventType;
    },
  },
} satisfies ServerHandlers;
const route: Promise<Response> = hooks.handle(request, handlers);
void route;
hooks.handle(request, { intercept: { toolBefore() { return { effects: [{ type: "deny", reason: "policy" }] }; } } });
const upload = attachments.parse(request);
const stream: ReadableStream<Uint8Array> = upload.body;
void stream;
attachments.response({ ref: "stored", size: upload.size, sha256: upload.sha256 });
// @ts-expect-error SDK supplies protocolVersion, not the application.
const bad: ServerReply<"tool.before"> = { effects: [], protocolVersion: "draft" };
// @ts-expect-error intercept handlers must return a reply, not void.
hooks.handle(request, { intercept: { toolBefore() {} } });
// @ts-expect-error observations cannot return control replies.
hooks.handle(request, { observe: { sessionEnd() { return { effects: [] }; } } });
// @ts-expect-error observation-only events cannot intercept.
hooks.handle(request, { intercept: { sessionEnd() { return { effects: [] }; } } });
// @ts-expect-error raw method-switch callbacks are no longer supported.
hooks.handle(request, () => ({ effects: [] }));
// @ts-expect-error descriptor digest is required.
attachments.response({ ref: "stored", size: 0 });
void bad;
declare const input: Readable;
declare const output: Writable;
const stdioOptions: StdioOptions = {
  stdin: input,
  stdout: output,
  signal: new AbortController().signal,
};
const serving: Promise<void> = serveStdio(handlers, stdioOptions);
void serving;
// @ts-expect-error stdio accepts the same typed table, not an HTTP callback.
serveStdio(() => new Response(null));
// @ts-expect-error stdio intercept handlers cannot return void.
serveStdio({ intercept: { toolBefore() {} } });

// Both actual request envelopes expose the same discriminated Event contract.
import type { Event, InterceptRequest, ObserveNotification, ContentReference, ContentUploadReceipt } from "agenthooksprotocol/server";
function consumeEvent(event: Event): string {
  // Open unknown event variants need explicit field checks even with known type strings.
  return typeof event.id === "string" ? event.id : "unknown";
}
declare const intercept: InterceptRequest;
declare const observe: ObserveNotification;
consumeEvent(intercept.params.event);
consumeEvent(observe.params.event);
const interceptEvent: Event = intercept.params.event;
const observeEvent: Event = observe.params.event;
const backToIntercept: InterceptRequest["params"]["event"] = observeEvent;
const backToObserve: ObserveNotification["params"]["event"] = interceptEvent;
void backToIntercept;
void backToObserve;
const reference: ContentReference = { ref: "stored" };
const receipt: ContentUploadReceipt = { ref: "stored", size: 0, sha256: "0".repeat(64) };
void reference;
void receipt;
// Extensible generated models allow arbitrary JSON keys statically; codecs enforce forbidden metadata.
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
const sameRequestEvent: Equal<InterceptRequest["params"]["event"], NonNullable<ObserveNotification["params"]>["event"]> = true;
const exactSharedEvent: Equal<InterceptRequest["params"]["event"], Event> = true;
void sameRequestEvent;
void exactSharedEvent;
