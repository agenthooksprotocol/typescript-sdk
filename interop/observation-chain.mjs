// @ts-check
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
/** @type {typeof import("@agenthooksprotocol/sdk/client")} */
const { Hooks, auth } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);

/**
 * The controller only schedules external fixture releases. The public client
 * owns all event construction, real transport, composition and observations.
 * @param {{id: string, requests: {a: {params: {event: Extract<import("@agenthooksprotocol/sdk/client").Event, {type: "tool.before"}>, capabilities: import("@agenthooksprotocol/sdk/client").Capabilities, state?: import("@agenthooksprotocol/sdk/client").BoundaryOptions["initialState"]}}}, chain: {subscriptions: {id: string, mode: 'intercept'|'observe', content: 'metadata'|'omit', failurePolicy: 'fail-open'|'fail-closed'}[], interrupt?: boolean, holdObservers?: boolean}}} row
 * @param {{transport: import("@agenthooksprotocol/sdk/client").Registration["hooks"][number]["transport"], authentication?: import("@agenthooksprotocol/sdk/client").Authentication, auth?: import("@agenthooksprotocol/sdk/client").AuthProvider, fetch?: typeof globalThis.fetch, control: (path: string, value?: object) => Promise<unknown>}} options
 */
export async function runChain(row, options) {
  const original = structuredClone(row.requests.a);
  const { source, type, ...input } = original.params.event;
  const id = input.id;
  const subs = row.chain.subscriptions;
  const interceptors = subs.filter((sub) => sub.mode === "intercept");
  const controller = new AbortController();
  const hooks = new Hooks(
    {
      protocolVersion: "draft",
      hooks: [
        {
          id: "interop.chain",
          transport: options.transport,
          ...(options.authentication
            ? { authentication: options.authentication }
            : {}),
          subscriptions: subs.map((sub) => ({
            mode: sub.mode,
            events: [type],
            content: { default: sub.content },
            ...(sub.mode === "intercept"
              ? { timeoutMs: 10000, failurePolicy: sub.failurePolicy }
              : {}),
          })),
        },
      ],
    },
    {
      source,
      capabilities: {
        [type]: {
          modes: ["intercept", "observe"],
          capabilities: original.params.capabilities,
        },
      },
      auth: options.auth ?? auth(),
      ...(options.fetch ? { fetch: options.fetch } : {}),
      observationTimeoutMs: 10000,
    },
  );
  let settled = false;
  let calledCount = 0;
  let observersReleased = false;
  try {
    const boundary = hooks.dispatch(type, input, {
      signal: controller.signal,
      ...(original.params.state !== undefined
        ? { initialState: original.params.state }
        : {}),
    });
    void boundary.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    while (!settled) {
      const receipts = await options.control("/receipts");
      if (
        !receipts ||
        typeof receipts !== "object" ||
        !("entries" in receipts) ||
        !Array.isArray(receipts.entries)
      )
        throw Error("Invalid controller receipts");
      const count = receipts.entries.filter(
        (entry) => entry.kind === "received" && entry.id === id,
      ).length;
      if (count > calledCount) {
        calledCount = count;
        if (row.chain.interrupt) {
          await options.control("/mark", {
            scenario: row.id,
            kind: "cancelled",
            id,
          });
          controller.abort();
        } else await options.control("/release", { id });
      }
      // HTTP observation completion is part of the boundary. Release a held
      // receiver while that boundary is pending, not after awaiting its return.
      if (
        row.chain.holdObservers &&
        !row.chain.interrupt &&
        !observersReleased &&
        receipts.entries.some(
          (entry) => entry.kind === "observer-blocked" && entry.id === id,
        )
      ) {
        await options.control("/mark", {
          scenario: row.id,
          kind: "observers-released",
          id,
        });
        await options.control("/release", { id: id + ":observers" });
        observersReleased = true;
      }
      if (!settled) await delay(1);
    }
    const result = await boundary;
    // A fast final interception can settle between receipt polls. Read the
    // receiver evidence once more before classifying uncalled subscriptions.
    const finalReceipts = await options.control("/receipts");
    if (
      !finalReceipts ||
      typeof finalReceipts !== "object" ||
      !("entries" in finalReceipts) ||
      !Array.isArray(finalReceipts.entries)
    )
      throw Error("Invalid controller receipts");
    calledCount = finalReceipts.entries.filter(
      (entry) => entry.kind === "received" && entry.id === id,
    ).length;
    await options.control("/mark", {
      scenario: row.id,
      kind: "chain-settled",
      id,
    });
    if (row.chain.interrupt) await options.control("/release", { id });
    const called = interceptors.slice(0, calledCount).map((sub) => sub.id);
    // Cancellation retires the original operation, including unstarted
    // observations. Explicit observe steps elsewhere are separate operations.
    const remaining = result.interrupted
      ? []
      : subs.filter((sub) => !called.includes(sub.id));
    if (
      result.interrupted &&
      finalReceipts.entries.some(
        (entry) => entry.kind === "observed" && entry.eventId === id,
      )
    )
      throw Error("Cancelled chain started an observation");
    // Stdio completes on frame write. Release after the first actual receipt,
    // before waiting for later notifications serialized behind that handler.
    if (row.chain.holdObservers && !observersReleased) {
      if (remaining.length) {
        await options.control("/wait-observed", { eventId: id, count: 1 });
        await options.control("/mark", {
          scenario: row.id,
          kind: "observers-released",
          id,
        });
      }
      await options.control("/release", { id: id + ":observers" });
    }
    if (remaining.length)
      await options.control("/wait-observed", {
        eventId: id,
        count: remaining.length,
      });
    await result.observations;
    return {
      called,
      failures: result.errors
        .filter(
          (/** @type {{code: string}} */ error) => error.code !== "INTERRUPTED",
        )
        .map(
          (/** @type {{subscriptionIndex: number}} */ error) =>
            subs[error.subscriptionIndex].id,
        ),
      observations: remaining.map((sub) => sub.id),
      input: result.event.tool.input,
    };
  } finally {
    await hooks.close();
  }
}
