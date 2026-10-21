import { content, duration, events, subscription, type Configuration } from "agenthooksprotocol";
import { Hooks } from "agenthooksprotocol/client";
import { hooks, type ServerHandlers } from "agenthooksprotocol/server";

const configuration = {
  subscriptions: [
    subscription.intercept({ events: [events.toolBefore], timeout: duration.milliseconds(750),
      failurePolicy: "fail-open", content: content.metadata() }),
    subscription.observe({ events: [events.toolAfter], content: content.metadata() }),
  ],
} satisfies Configuration;

const backend = { configuration, intercept: { toolBefore: () => ({}) } } satisfies ServerHandlers;
void hooks.handle(new Request("https://backend.test/hooks"), backend);
void new Hooks({ protocolVersion: "draft", hooks: [{ id: "example.backend",
  transport: { type: "http", url: "https://backend.test/hooks" }, ...configuration }] }, {
  source: "urn:test:configuration", harness: { name: "test", version: "1" },
  capabilities: { toolBefore: { intercept: { deny: true } }, toolAfter: { observe: true } },
});

subscription.intercept({ events: [events.toolBefore],
  // @ts-expect-error duration units must be explicit
  timeout: 750, failurePolicy: "fail-open", content: content.metadata() });
// @ts-expect-error required failure policy cannot be omitted
subscription.intercept({ events: [events.toolBefore], timeout: duration.milliseconds(750), content: content.metadata() });
// @ts-expect-error content selection is explicit
subscription.observe({ events: [events.toolAfter] });

subscription.intercept({
  // @ts-expect-error observation-only events cannot be intercepted
  events: [events.sessionEnd], timeout: duration.milliseconds(750),
  failurePolicy: "fail-open", content: content.metadata(),
});
