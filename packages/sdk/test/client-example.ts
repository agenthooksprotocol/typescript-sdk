import { readFile } from "node:fs/promises";
import { Hooks, type EventCapabilities } from "@agenthooksprotocol/sdk/client";

// Hooks validates registration; JSON.parse alone does not validate it.
const config: unknown = JSON.parse(await readFile("hooks.json", "utf8"));
const capabilities: EventCapabilities = {
  "tool.before": { effects: ["deny"] },
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
      call: { id: "read-1" },
      path: "native",
      tool: { name: "read_file", origin: "native", input: args },
    },
    { initialState: { permission: "none", candidate: null } },
  );

  for (const error of result.errors) console.error(error);
  const denied = result.state.permission === "deny";
  if (result.interrupted || denied) {
    throw new Error("File read interrupted or denied by hooks");
  }

  // Only deny is granted, so hooks cannot rewrite args. The host executes
  // the operation after its own authorization and path checks.
  console.log(await readFile(args.path, "utf8"));
} finally {
  await hooks.close();
}
