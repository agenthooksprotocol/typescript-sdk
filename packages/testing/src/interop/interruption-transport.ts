/** Real public client; only backend scripts and barriers belong to the fixture. */
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  Hooks,
  auth,
  type BoundaryResult,
  type BoundaryInput,
  type Capabilities,
  type ToolBeforeEffect,
} from "agenthooksprotocol/client";
import { openBackend } from "./interruption-server.js";

export interface InterruptionOperation {
  response: Promise<BoundaryResult<"tool.before">>;
  received: Promise<void>;
  cancel(): void;
  release(): Promise<void>;
  routes: { received: Promise<void>; release(): Promise<void> }[];
}
export interface RouteScript {
  effects: ToolBeforeEffect[];
  raw?: string;
  hold?: boolean;
}
export async function openInterruptionTransport(
  kind: "http" | "stdio",
  capabilities: Capabilities,
  failurePolicy: "fail-open" | "fail-closed" = "fail-open",
  timeoutMs = 10000,
  routeCount = 1,
) {
  const backends = await Promise.all(
    Array.from({ length: routeCount }, () => openBackend()),
  );
  const client = new Hooks(
    {
      protocolVersion: "draft",
      hooks: backends.map((backend, index) => ({
        id: `test.interruption${index}`,
        transport:
          kind === "http"
            ? { type: "http", url: backend.url }
            : {
                type: "stdio",
                lifecycle: "persistent",
                command: process.execPath,
                args: [
                  fileURLToPath(
                    new URL("./interruption-server.js", import.meta.url),
                  ),
                  "--stdio",
                  backend.url,
                ],
              },
        subscriptions: [
          {
            mode: "intercept",
            events: ["tool.before"],
            timeoutMs,
            failurePolicy,
            content: { default: "metadata" },
          },
        ],
      })),
    },
    {
      source: "urn:ahp:interruption",
      capabilities: { "tool.before": capabilities },
      auth: auth(),
    },
  );
  await client.initialized;
  return {
    requests: backends[0]!.requests,
    routeRequests: backends.map((backend) => backend.requests),
    start(
      id: string,
      input: BoundaryInput<"tool.before">["tool"]["input"],
      effects: ToolBeforeEffect[],
      raw?: string,
      laterRoutes: RouteScript[] = [],
    ): InterruptionOperation {
      const scripts = backends.map((backend, index) => {
        const config = laterRoutes[index - 1];
        const script = backend.configure(
          id,
          index === 0 ? effects : (config?.effects ?? []),
          index === 0 ? raw : config?.raw,
        );
        if (index > 0 && !config?.hold) script.released.resolve();
        return script;
      });
      const routes = scripts.map((script) => ({
        received: script.received.promise,
        async release() {
          script.released.resolve();
          await script.replied.promise;
        },
      }));
      const controller = new AbortController();
      const response = client.dispatch(
        "tool.before",
        {
          id,
          time: "2026-01-01T00:00:00Z",
          session: { id: "interruption" },
          call: { id },
          path: "native",
          tool: { origin: "native", name: "task", kind: "task", input },
        },
        { signal: controller.signal },
      );
      return {
        response,
        routes,
        received: routes[0]!.received,
        cancel: () => controller.abort(),
        release: () => routes[0]!.release(),
      };
    },
    async dispose() {
      await client.close();
      await Promise.all(backends.map((backend) => backend.close()));
    },
  };
}
