import { readFile } from "node:fs/promises";
import {
  Hooks,
  capabilities as capability,
  events,
  state,
  Permission,
  type EventCapabilities,
} from "@agenthooksprotocol/sdk/client";

// Hooks validates registration; JSON.parse alone does not validate it.
const config: unknown = JSON.parse(await readFile("hooks.json", "utf8"));
const capabilities: EventCapabilities = {
  [events.toolBefore]: capability.intercept().deny(),
};
const hooks = new Hooks(config, {
  source: "urn:example:agent",
  capabilities,
});

type ReadFileArguments = { path: string };
const args: ReadFileArguments = { path: "README.md" };

try {
  // Boundary calls wait for initialization internally.
  const result = await hooks.toolBefore(
    {
      callId: "read-1",
      path: "native",
      name: "read_file",
      origin: "native",
      input: args,
    },
    { initialState: state.initial(Permission.None) },
  );

  for (const diagnostic of result.diagnostics) console.error(diagnostic);
  const denied = result.permission === Permission.Deny;
  if (result.interrupted || denied) {
    throw new Error("File read interrupted or denied by hooks");
  }

  // Only deny is granted, so hooks cannot rewrite args. The host executes
  // the operation after its own authorization and path checks.
  console.log(await readFile(args.path, "utf8"));
} finally {
  await hooks.close();
}
