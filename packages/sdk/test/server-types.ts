import {
  hooks,
  attachments,
  type Message,
  type InterceptResult,
  type CapabilitiesResult,
} from "agenthooksprotocol/server";
declare const request: Request;
declare const user: { id: string };
declare const policyService: {
  handle(
    message: Message,
    user: { id: string },
  ): Promise<InterceptResult | CapabilitiesResult | void>;
};
const route: Promise<Response> = hooks.handle(request, (message) =>
  policyService.handle(message, user),
);
void route;
hooks.handle(request, (message) => {
  switch (message.method) {
    case "hooks/intercept": {
      const eventId: string = typeof message.params.event.id === "string" ? message.params.event.id : "unknown";
      void eventId;
      return { effects: [{ type: "deny", reason: "policy" }] };
    }
    case "hooks/observe":
      return;
    case "hooks/capabilities":
      return {
        manifest: {
          authentication: [],
          contentCategories: [],
          correlationIdentityFields: [],
          events: [],
          gaps: [],
          limits: {},
          managedPolicy: { disableable: true, scopes: [] },
          toolPaths: [],
          transports: ["http"],
        },
      };
  }
});
const upload = attachments.parse(request);
const stream: ReadableStream<Uint8Array> = upload.body;
void stream;
attachments.response({
  ref: "stored",
  size: upload.size,
  sha256: upload.sha256,
});
// @ts-expect-error SDK supplies protocolVersion, not the application.
const bad: InterceptResult = { effects: [], protocolVersion: "draft" };
// @ts-expect-error exact optional fields do not accept explicit undefined.
const badOptional: InterceptResult = { effects: [], extensions: undefined };
// @ts-expect-error result fields are mandatory.
hooks.handle(request, () => ({ status: "ok" }));
// @ts-expect-error descriptor digest is required.
attachments.response({ ref: "stored", size: 0 });
void bad;
void badOptional;

import {
  serveStdio,
  type StdioOptions,
} from "agenthooksprotocol/server/stdio";
import type { Readable, Writable } from "node:stream";
declare const input: Readable;
declare const output: Writable;
const stdioOptions: StdioOptions = {
  stdin: input,
  stdout: output,
  signal: new AbortController().signal,
};
const serving: Promise<void> = serveStdio(
  (request) => hooks.handle(request, () => ({ effects: [] })),
  stdioOptions,
);
void serving;
serveStdio(() => new Response(null));
// @ts-expect-error A stdio handler returns a Web Response, not a protocol result.
serveStdio(() => ({ effects: [] }));

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
