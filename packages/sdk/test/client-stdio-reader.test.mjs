import test from "node:test";
import assert from "node:assert/strict";
import { subscribe, unsubscribe } from "node:diagnostics_channel";
import {
  BackendTransport,
  STDIO_DIAGNOSTICS_CHANNEL,
} from "agenthooksprotocol/client";

const request = (id) => ({
  jsonrpc: "2.0",
  id,
  method: "hooks/capabilities",
  params: { protocolVersion: "draft" },
});
const stdio = (code, lifecycle = "persistent") =>
  new BackendTransport(
    {
      id: "reader.backend",
      subscriptions: [],
      transport: {
        type: "stdio",
        command: process.execPath,
        args: ["-e", code],
        lifecycle,
      },
    },
    () => {
      throw new Error("stdio must not fetch");
    },
  );
// Each request carries raw lines to write `before` and `after` its reply, all in
// one write so trailing lines arrive while no request is in flight.
const scripted = `const readline = require('node:readline');
readline.createInterface({input: process.stdin}).on('line', line => {
  const m = JSON.parse(line);
  const p = m.params;
  const reply = p.reply === false ? [] : [JSON.stringify({jsonrpc:'2.0',id:m.id,result:{pid:process.pid}})];
  process.stdout.write([...(p.before ?? []), ...reply, ...(p.after ?? [])].map(l => l + '\\n').join(''));
});`;
const noisy = (id, { before, after, reply = true } = {}) => ({
  ...request(id),
  params: { protocolVersion: "draft", before: before ?? [], after: after ?? [], reply },
});
function record() {
  const seen = [];
  const listener = (message) => seen.push(message);
  subscribe(STDIO_DIAGNOSTICS_CHANNEL, listener);
  return {
    seen,
    // Trailing frames are processed after the reply resolves; wait for them.
    async settle(count) {
      while (seen.length < count) await new Promise((r) => setTimeout(r, 5));
    },
    stop: () => unsubscribe(STDIO_DIAGNOSTICS_CHANNEL, listener),
  };
}
const summary = (seen) =>
  seen.map(({ kind, code, strikes, terminated }) => [
    kind,
    code,
    strikes,
    terminated,
  ]);

test(
  "persistent stdio discards unsolicited frames with a diagnostic",
  { timeout: 5000 },
  async () => {
    const diagnostics = record();
    const transport = stdio(scripted);
    try {
      const stray = JSON.stringify({ jsonrpc: "2.0", id: "stray", result: {} });
      const first = await transport.request(noisy(1, { before: [stray] }));
      const second = await transport.request(request(2));
      assert.equal(first.id, 1);
      assert.equal(second.id, 2);
      assert.equal(first.result.pid, second.result.pid);
      assert.deepEqual(diagnostics.seen, [
        {
          backendId: "reader.backend",
          kind: "unsolicited",
          strikes: 0,
          terminated: false,
        },
      ]);
    } finally {
      diagnostics.stop();
      await transport.close();
    }
  },
);

test(
  "persistent stdio tolerates isolated malformed frames without respawning",
  { timeout: 5000 },
  async () => {
    const diagnostics = record();
    const transport = stdio(scripted);
    try {
      const method = JSON.stringify({
        jsonrpc: "2.0",
        method: "hooks/observe",
        params: {},
      });
      const first = await transport.request(
        noisy(1, { after: ["not json", method] }),
      );
      await diagnostics.settle(2);
      const second = await transport.request(noisy(2, { after: ["log line"] }));
      await diagnostics.settle(3);
      const third = await transport.request(request(3));
      assert.equal(first.result.pid, second.result.pid);
      assert.equal(second.result.pid, third.result.pid);
      assert.deepEqual(summary(diagnostics.seen), [
        ["malformed", "MALFORMED_JSON", 1, false],
        ["malformed", "MALFORMED_JSON_RPC", 2, false],
        // The valid reply to request 2 reset the consecutive count.
        ["malformed", "MALFORMED_JSON", 1, false],
      ]);
    } finally {
      diagnostics.stop();
      await transport.close();
    }
  },
);

test(
  "a malformed frame fails only the in-flight request, not the backend",
  { timeout: 5000 },
  async () => {
    const transport = stdio(scripted);
    try {
      await assert.rejects(
        transport.request(noisy(1, { before: ["not json"], reply: false })),
        {
          name: "HookOperationalError",
          code: "MALFORMED_JSON",
          message: "Malformed backend response",
        },
      );
      const bad = JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        result: {},
        error: { code: -1, message: "x" },
      });
      await assert.rejects(
        transport.request(noisy(2, { before: [bad], reply: false })),
        {
          code: "MALFORMED_JSON_RPC",
        },
      );
      const first = await transport.request(request(3));
      const second = await transport.request(request(4));
      assert.equal(first.result.pid, second.result.pid);
    } finally {
      await transport.close();
    }
  },
);

test(
  "persistent stdio terminates after repeated malformed frames",
  { timeout: 5000 },
  async () => {
    const diagnostics = record();
    const transport = stdio(scripted);
    try {
      const first = await transport.request(
        noisy(1, { after: ["a", "b", "c"] }),
      );
      await diagnostics.settle(3);
      assert.deepEqual(summary(diagnostics.seen), [
        ["malformed", "MALFORMED_JSON", 1, false],
        ["malformed", "MALFORMED_JSON", 2, false],
        ["malformed", "MALFORMED_JSON", 3, true],
      ]);
      // The next request starts a fresh backend.
      const next = await transport.request(request(2));
      assert.equal(next.id, 2);
      assert.notEqual(next.result.pid, first.result.pid);
    } finally {
      diagnostics.stop();
      await transport.close();
    }
  },
);

test(
  "per-event stdio wraps non-JSON output as an operational error",
  { timeout: 5000 },
  async () => {
    const transport = stdio(
      `process.stdin.resume();process.stdout.write('not json\\n');`,
      "per_event",
    );
    try {
      await assert.rejects(
        transport.request(request(1), AbortSignal.timeout(1000)),
        { name: "HookOperationalError", code: "MALFORMED_JSON" },
      );
    } finally {
      await transport.close();
    }
  },
);
