// Closes Hooks while one discovery hangs and a stdio discovery has succeeded, then
// reports how many spawned stdio backends were never closed and exits explicitly.
import { Hooks, nodeSpawn } from "agenthooksprotocol/client";
import { content, duration, events, subscription } from "agenthooksprotocol";

const phase = process.argv[2];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const configuration = { subscriptions: [subscription.intercept({ events: [events.toolBefore], timeout: duration.milliseconds(750),
  failurePolicy: "fail-open", content: content.metadata() })] };
const script = `require('node:readline').createInterface({ input: process.stdin }).on('line', line => {
  const request = JSON.parse(line);
  process.stdout.write(JSON.stringify(process.env.AHP_FAIL ? { jsonrpc: '2.0', id: request.id, error: { code: -32004, message: 'unavailable' } }
    : { jsonrpc: '2.0', id: request.id, result: { protocolVersion: 'draft', configuration: ${JSON.stringify(configuration)} } }) + '\\n');
});`;
const processes = [];
let hang = phase === "initialization", hanging;
const reached = new Promise(resolve => { hanging = resolve; });
const client = new Hooks({ protocolVersion: "draft", hooks: [
  { id: "test.stdio", transport: { type: "stdio", command: process.execPath, args: ["-e", script], lifecycle: "persistent" } },
  { id: "test.http", transport: { type: "http", url: "https://backend.test/hooks" } },
] }, {
  source: "urn:test:configuration", harness: { name: "test", version: "1" },
  capabilities: { toolBefore: { intercept: { deny: true } } },
  configurationRetry: { initialDelayMs: 20, maxDelayMs: 20 },
  async fetch(_url, init) {
    if (!hang) return new Response(null, { status: 503 });
    hanging();
    return new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason)));
  },
  spawn(request) {
    const child = nodeSpawn(phase === "re-attempt" && processes.length === 0
      ? { ...request, env: { ...request.env, AHP_FAIL: "1" } } : request);
    const entry = { closed: false, child };
    processes.push(entry);
    child.onClose(() => { entry.closed = true; });
    return { write: child.write.bind(child), onStdout: child.onStdout.bind(child), onError: child.onError.bind(child),
      onClose: child.onClose.bind(child), kill() { entry.closed = true; child.kill(); } };
  },
});
if (phase === "re-attempt") {
  await client.initialized;
  await sleep(40);
  hang = true;
  void client.toolBefore({ callId: "call", name: "read", path: "native", origin: "native", input: {} }).catch(() => {});
}
await reached;
// Let the stdio discovery succeed while the HTTP one is still pending.
await sleep(300);
await client.close();
// A gracefully closed persistent backend exits shortly after its stdin ends.
await sleep(500);
console.log(JSON.stringify({ spawned: processes.length, leaked: processes.filter(entry => !entry.closed).length }));
for (const entry of processes) entry.child.kill();
process.exit(0);
