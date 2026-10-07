import { isDeepStrictEqual } from "node:util";
import { mutableValues } from "./settlement.mjs";

/** Present the actual public Hooks result. This enacts accepted decisions; it
 * neither validates effects nor replays modifications to reconstruct an event.
 * In particular, an SDK-accepted invalid compound cannot become a rejection here.
 */
export function summarizeAccepted(request, result) {
  const { event, response } = result;
  const effects = response.result.effects;
  const prior = request.params.state ?? { permission: "none", candidate: null };
  const input = structuredClone(event.tool?.input ?? event.input ?? {});
  const values = mutableValues(event);
  const changed =
    !isDeepStrictEqual(
      input,
      structuredClone(
        request.params.event.tool?.input ?? request.params.event.input ?? {},
      ),
    ) || !isDeepStrictEqual(values, mutableValues(request.params.event));
  const decision =
    prior.permission === "deny" || effects.some((e) => e.type === "deny")
      ? "deny"
      : prior.permission === "ask" || effects.some((e) => e.type === "ask")
        ? "ask"
        : "allow";
  const flows = effects.filter((e) => e.type === "flow");
  const flow =
    prior.flow === "stop" || flows.some((e) => e.operation === "stop")
      ? "stop"
      : prior.flow === "continue" ||
          flows.some((e) => e.operation === "continue")
        ? "continue"
        : undefined;
  const candidate =
    effects.findLast((e) => e.type === "return") ??
    (changed ? null : prior.candidate);
  const instructions = [
    ...(prior.instructions ?? []),
    ...flows.flatMap((e) =>
      e.operation === "continue" && typeof e.instruction === "string"
        ? [e.instruction]
        : [],
    ),
  ];
  const injections = [
    ...(prior.injections ?? []),
    ...effects.filter((e) => e.type === "inject"),
  ];
  // A budget is a host scheduling counter, not an accepted effect. Report it
  // only when scheduling state exists; mere advertised capability does not act.
  const budget = request.params.capabilities.flow?.remainingContinuations;
  const scheduling = flow !== undefined || prior.instructions !== undefined;
  const remaining =
    budget === undefined
      ? undefined
      : budget -
        (flow === "continue" && prior.flow !== "continue" ? 1 : 0) +
        (flow === "stop" && prior.flow === "continue" ? 1 : 0);
  return {
    ...(Object.keys(values).length ? { values } : {}),
    decision,
    executed:
      event.type === "tool.before" &&
      decision === "allow" &&
      candidate == null &&
      flow !== "stop" &&
      !result.interrupted,
    input,
    messages: effects.filter((e) => e.type === "message").map((e) => e.text),
    ...(candidate != null && decision === "allow" && flow !== "stop"
      ? { result: structuredClone(candidate.value) }
      : {}),
    ...(flow ? { flow } : {}),
    ...(scheduling &&
    (remaining !== undefined ||
      prior.instructions !== undefined ||
      instructions.length)
      ? {
          continuationInstructions: instructions,
          ...(remaining !== undefined
            ? { continuationRemaining: remaining }
            : {}),
        }
      : {}),
    ...(prior.injections !== undefined || injections.length
      ? { injections: structuredClone(injections) }
      : {}),
  };
}
