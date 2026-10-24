import { content, duration, events, subscription, type Configuration, type ConfigurationContext as RootContext } from "agenthooksprotocol";
import { hooks, type ServerHandlers, type ConfigurationContext, type ConfigurationHandler } from "agenthooksprotocol/server";
import { serveStdio } from "agenthooksprotocol/server/stdio";

const configuration: Configuration = { subscriptions: [subscription.intercept({
  events: [events.toolBefore], timeout: duration.milliseconds(750),
  failurePolicy: "fail-open", content: content.metadata(),
})] };
const staticHandlers: ServerHandlers = { configuration };
const dynamicHandlers = { configuration: async (ctx: ConfigurationContext) => {
  const sameContext: RootContext = ctx;
  const signal: AbortSignal = ctx.signal;
  const method: "hooks/configuration" = ctx.request.method;
  void [sameContext, signal, method];
  // @ts-expect-error The protocol does not fabricate authentication identity.
  void ctx.principal;
  return configuration;
} } satisfies ServerHandlers;
const sync: ConfigurationHandler = () => configuration;
const asynchronous: ConfigurationHandler = async () => configuration;
void [sync, asynchronous];
void hooks.handle(new Request("https://backend.test/hooks"), staticHandlers);
void hooks.handle(new Request("https://backend.test/hooks"), dynamicHandlers);
void serveStdio(dynamicHandlers);
// @ts-expect-error A dynamic callback must return configuration, not no result.
const noResult: ServerHandlers = { configuration: () => undefined };
// @ts-expect-error Null is not an opt-out or a configuration response.
const nil: ServerHandlers = { configuration: async () => null };
void [noResult, nil];
