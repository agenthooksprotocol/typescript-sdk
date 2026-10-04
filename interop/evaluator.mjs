export { summarizeAccepted } from "./accepted-summary.mjs";
import { isDeepStrictEqual } from "node:util";
export function matches(actual, expected) {
  return (
    Object.entries(expected).every(([key, value]) =>
      isDeepStrictEqual(actual[key], value),
    ) &&
    [
      "result",
      "flow",
      "injections",
      "continuationRemaining",
      "continuationInstructions",
      "values",
    ].every(
      (key) => Object.hasOwn(expected, key) || !Object.hasOwn(actual, key),
    ) &&
    (!(
      actual.decision === "deny" ||
      actual.decision === "ask" ||
      actual.flow === "stop"
    ) ||
      !Object.hasOwn(actual, "result"))
  );
}
