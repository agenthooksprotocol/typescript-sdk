import {
  hooks,
  attachments,
  type Message,
  type InterceptResult,
  type CapabilitiesResult,
} from "@agenthooksprotocol/sdk/server";
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
      const eventId: string = message.params.event.id;
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
} from "@agenthooksprotocol/sdk/server/stdio";
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
