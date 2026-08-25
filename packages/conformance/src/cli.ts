#!/usr/bin/env node
import { runConformance } from "./index.js";

function usage(): never {
  process.stderr.write("Usage: ahp-conformance [--timeout-ms N] -- <command> [args...]\n");
  process.exit(2);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  let timeoutMs = 1_000;
  if (argv[0] === "--timeout-ms") {
    timeoutMs = Number(argv[1]);
    argv.splice(0, 2);
  }
  if (argv[0] === "--") argv.shift();
  const command = argv.shift();
  if (command === undefined || !Number.isInteger(timeoutMs) || timeoutMs <= 0) usage();
  const report = await runConformance({ command, args: argv, timeoutMs });
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (!report.ok) process.exitCode = 1;
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
