/** Typed fixture bridge. The public client owns this process and NDJSON framing.
 * The HTTP receiver scripts raw/adversarial replies; no client validation here. */
import { createInterface } from "node:readline";
import process from "node:process";
const url = process.argv[2];
if (!url) throw new Error("Missing fixture URL");
for await (const line of createInterface({ input: process.stdin })) {
  const response = await fetch(url, { method: "POST", body: line });
  process.stdout.write((await response.text()) + "\n");
}
