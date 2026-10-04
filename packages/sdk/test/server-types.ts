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
