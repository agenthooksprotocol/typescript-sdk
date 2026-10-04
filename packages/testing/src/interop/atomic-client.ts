import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import process from "node:process";
import { hooks as serverHooks } from "@agenthooksprotocol/sdk/server";
import {
  Hooks,
  auth,
  type BoundaryResult,
} from "@agenthooksprotocol/sdk/client";
import {
  parseInterceptResponse,
  type PendingState,
  type Capabilities,
  type InterceptRequest,
  type JsonValue,
  type Effect,
} from "@agenthooksprotocol/sdk/draft";

interface Subscriber {
  id: string;
  failurePolicy: "fail-open" | "fail-closed";
  capabilities: Capabilities;
  response: unknown;
  rawResponse?: string;
  httpStatus?: number;
}
export interface AtomicOutcome {
  state: PendingState;
  actions: string[];
  trace: string[];
  failures: number;
  executions: number;
  emittedMessages: string[];
  requests: unknown[];
}
export interface AtomicScenario {
  id: string;
  initial: PendingState;
  subscribers: Subscriber[];
  managedPolicy: "allow" | "deny";
  expected: AtomicOutcome;
}
export interface AtomicRow {
  client: "public-hooks";
  effects: Effect[];
  effectiveInput: unknown;
  hostAccepted: boolean;
  sdkErrors: BoundaryResult<"tool.before">["errors"];
  id: string;
  transport: "http" | "stdio";
  actual: AtomicOutcome;
  expected: AtomicOutcome;
}
export function atomicScenarios(): AtomicScenario[] {
  return JSON.parse(
    readFileSync(
      new URL("../../../interop/atomic-scenarios.json", import.meta.url)
        .pathname,
      "utf8",
    ),
  ).scenarios;
}

/** Script only the receiver. Hooks owns wire framing, validation and composition. */
export async function runAtomicInterop(): Promise<AtomicRow[]> {
  const rows: AtomicRow[] = [];
  for (const transport of ["http", "stdio"] as const) {
    for (const scenario of atomicScenarios()) {
      const requests: InterceptRequest[] = [];
      const occurrence = scenario.subscribers[0]!.id;
      const replies = scenario.subscribers.map((subscriber) => {
        if (subscriber.rawResponse !== undefined) return subscriber.rawResponse;
        const response = structuredClone(subscriber.response) as Record<
          string,
          unknown
        >;
        // Only fixture correlation IDs are translated. Deliberately incorrect IDs
        // and malformed raw frames must reach Hooks unchanged.
        if (response.id === subscriber.id) response.id = occurrence;
        return JSON.stringify(response);
      });
      const server = createServer(
        async (
          request: AsyncIterable<Uint8Array> & { url?: string },
          response: {
            writeHead(status: number, headers?: Record<string, string>): void;
            end(body?: string): void;
          },
        ) => {
          const index = Number(request.url?.slice(1));
          const subscriber = scenario.subscribers[index];
          if (!subscriber) {
            response.writeHead(404);
            response.end();
            return;
          }
          let body = "";
          for await (const chunk of request) body += chunk;
          requests.push(JSON.parse(body) as InterceptRequest);
          if (scenario.expected.trace.includes(`reject:${subscriber.id}`)) {
            // Only deliberately adversarial receivers bypass the server helper.
            // The public client must receive/reject the original bad frame.
            response.writeHead(subscriber.httpStatus ?? 200, {
              "content-type": "application/json",
            });
            response.end(replies[index]);
            return;
          }
          const scripted = parseInterceptResponse(replies[index]!);
          if (!scripted.ok)
            throw new Error("Invalid positive fixture response");
          // Public server callbacks provide effects, never protocol envelopes.
          // Preserve result extensions (the extensible-envelope fixture) while
          // letting the helper own correlation, protocolVersion and validation.
          const { protocolVersion: _, ...result } = scripted.value.result;
          const handled = await serverHooks.handle(
            new Request("http://atomic.test/hooks", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body,
            }),
            () => result,
          );
          response.writeHead(handled.status, {
            "content-type": "application/json",
          });
          response.end(await handled.text());
        },
      );
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      const base = `http://127.0.0.1:${server.address().port}`;
      const hooks = new Hooks(
        {
          protocolVersion: "draft",
          hooks: scenario.subscribers.map((subscriber, index) => ({
            id: `interop.${subscriber.id}`,
            transport:
              transport === "http"
                ? { type: "http", url: `${base}/${index}` }
                : {
                    type: "stdio",
                    command: process.execPath,
                    args: [
                      new URL("./atomic-backend.js", import.meta.url).pathname,
                      `${base}/${index}`,
                    ],
                    lifecycle: "persistent",
                  },
            subscriptions: [
              {
                mode: "intercept",
                events: ["tool.before"],
                timeoutMs: 5000,
                failurePolicy: subscriber.failurePolicy,
                content: { default: "metadata" },
              },
            ],
          })),
        },
        {
          source: "urn:ahp:interop",
          capabilities: {
            "tool.before": scenario.subscribers[0]!.capabilities,
          },
          auth: auth(),
        },
      );
      try {
        // All multisubscriber fixtures advertise the same capability set. A
        // public boundary's advertisement belongs to the occurrence, not route.
        for (const subscriber of scenario.subscribers)
          if (
            JSON.stringify(subscriber.capabilities) !==
            JSON.stringify(scenario.subscribers[0]!.capabilities)
          )
            throw new Error(
              "Fixture needs heterogeneous per-route capabilities",
            );
        const result = await hooks.toolBefore(
          {
            id: occurrence,
            time: "2026-01-01T00:00:00Z",
            session: { id: "interop" },
            call: { id: "call-1" },
            path: "native",
            tool: {
              origin: "native",
              name: "task",
              kind: "task",
              input: structuredClone(scenario.initial.input) as Record<
                string,
                JsonValue
              >,
            },
          },
          {
            state: {
              permission: scenario.initial.denied
                ? "deny"
                : scenario.initial.permission === "native"
                  ? "none"
                  : scenario.initial.permission,
              candidate:
                scenario.initial.candidate === null
                  ? null
                  : { value: scenario.initial.candidate.value as JsonValue },
            },
          },
        );
        if (result.interrupted || (await result.observations).length)
          throw new Error(
            `Unexpected interruption/observation: ${scenario.id}`,
          );
        rows.push({
          client: "public-hooks",
          effects: result.response.result.effects,
          effectiveInput: result.event.tool.input,
          hostAccepted: validHostInput(result.event.tool.input),
          sdkErrors: result.errors,
          id: scenario.id,
          transport,
          actual: enact(scenario, result, requests),
          expected: scenario.expected,
        });
      } finally {
        await hooks.close();
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        });
      }
    }
  }
  return rows;
}

/** Enact only responses the SDK accepted. No response staging or failure policy
 * is implemented here: acceptance/errors and effective input come from Hooks.
 * Trace acceptance is reconstructed after the boundary; the API has no per-route
 * acceptance callback. Candidate provenance and approval are host-owned fields. */
function enact(
  scenario: AtomicScenario,
  result: BoundaryResult<"tool.before">,
  requests: InterceptRequest[],
): AtomicOutcome {
  const state = structuredClone(scenario.initial);
  const trace: string[] = [],
    emittedMessages: string[] = [];
  for (const [index, subscriber] of scenario.subscribers.entries()) {
    const request = requests[index];
    if (!request)
      throw new Error(
        `Missing public delivery: ${scenario.id}/${subscriber.id}`,
      );
    trace.push(`dispatch:${subscriber.id}`);
    const error = result.errors.find(
      (error) => error.backendId === `interop.${subscriber.id}`,
    );
    if (error) {
      trace.push(`reject:${subscriber.id}`, `failure:${error.failurePolicy}`);
      // Synthetic denial is produced by Hooks, not applied from registration.
      if (error.syntheticDenial) state.denied = true;
      continue;
    }
    const effective = requests[index + 1]?.params.event ?? result.event;
    if (effective.type !== "tool.before")
      throw new Error("Unexpected effective event");
    const input = effective.tool.input as Record<string, unknown>;
    if (!sameInput(state.input, input)) {
      state.candidate = null;
      if (state.permission === "allow") state.permission = "native";
      if (state.approval === "approved") state.approval = "pending";
    }
    state.input = structuredClone(input);
    // Public errors established atomic acceptance. Decode the accepted fixture
    // only to attach host provenance/messages that BoundaryResult does not tag.
    const accepted = parseInterceptResponse(
      subscriber.rawResponse ?? JSON.stringify(subscriber.response),
    );
    if (!accepted.ok)
      throw new Error("SDK accepted an invalid fixture response");
    trace.push(`accept:${subscriber.id}`);
    for (const effect of accepted.value.result.effects) {
      switch (effect.type) {
        case "return":
          state.candidate = {
            value: effect.value,
            supplier: subscriber.id,
            input: structuredClone(state.input),
          };
          break;
        case "allow":
          if (state.permission !== "ask") state.permission = "allow";
          break;
        case "ask":
          state.permission = "ask";
          state.approval = "pending";
          break;
        case "deny":
          state.denied = true;
          break;
        case "message":
          state.messages.push(effect.text);
          emittedMessages.push(effect.text);
          trace.push(`message:${effect.text}`);
          break;
      }
    }
    if (state.denied) state.candidate = null;
  }
  const actions = [
    "policy",
    !validHostInput(result.event.tool.input)
      ? "host-input-rejected"
      : state.denied || scenario.managedPolicy === "deny"
        ? "blocked"
        : state.approval === "pending" && state.permission !== "allow"
          ? "approval-required"
          : state.candidate
            ? `candidate:${state.candidate.supplier}`
            : "execute",
  ];
  trace.push(...actions);
  return {
    state,
    actions,
    trace,
    failures: result.errors.length,
    executions: actions.includes("execute") ? 1 : 0,
    emittedMessages,
    requests,
  };
}
function sameInput(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (
    a === null ||
    b === null ||
    typeof a !== "object" ||
    typeof b !== "object"
  )
    return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>,
    right = b as Record<string, unknown>;
  return (
    Object.keys(left).length === Object.keys(right).length &&
    Object.keys(left).every(
      (key) => Object.hasOwn(right, key) && sameInput(left[key], right[key]),
    )
  );
}

// Synthetic fixture tool schema; AHP itself does not constrain task to be positive.
function validHostInput(input: Record<string, unknown>): boolean {
  return (
    typeof input.task === "number" &&
    Number.isInteger(input.task) &&
    input.task > 0
  );
}
