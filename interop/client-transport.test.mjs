import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(
  new URL("../packages/sdk/package.json", import.meta.url),
);
const { BackendTransport } = await import(
  require.resolve("@agenthooksprotocol/sdk/client")
);

const request = (id = 1) => ({
  jsonrpc: "2.0",
  id,
  method: "hooks/capabilities",
  params: { protocolVersion: "draft" },
});
const notification = { jsonrpc: "2.0", method: "hooks/observe", params: {} };
const backend = (transport) => ({
  id: "test.backend",
  subscriptions: [],
  transport,
});
const unusedFetch = () => {
  throw new Error("stdio must not fetch");
};
const stdio = (code, lifecycle = "persistent") =>
  new BackendTransport(
    backend({
      type: "stdio",
      command: process.execPath,
      args: ["-e", code],
      lifecycle,
    }),
    unusedFetch,
  );
const echo = `const readline = require('node:readline');
let count = 0;
readline.createInterface({input: process.stdin}).on('line', line => {
  const m = JSON.parse(line); count++;
  if ('id' in m) process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{pid:process.pid,count}})+'\\n');
});`;

test("HTTP uses the injected authenticated fetch and correlated JSON-RPC envelopes", async () => {
  const calls = [];
  const transport = new BackendTransport(
    backend({ type: "http", url: "https://backend.test/hooks" }),
    async (url, init) => {
      calls.push({ url, init });
      const message = JSON.parse(init.body);
      return "id" in message
        ? Response.json({
            jsonrpc: "2.0",
            id: message.id,
            result: { ok: true },
          })
        : new Response(null, { status: 202 });
    },
  );
  try {
    assert.deepEqual(await transport.request(request()), {
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    });
    await transport.notify(notification);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, "https://backend.test/hooks");
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.redirect, "error");
    assert.equal(
      new Headers(calls[0].init.headers).get("content-type"),
      "application/json",
    );
    assert.ok(calls[0].init.signal instanceof AbortSignal);
    assert.deepEqual(JSON.parse(calls[1].init.body), notification);
  } finally {
    await transport.close();
  }
});

test("HTTP rejects invalid status, media type, ID and notification bodies", async () => {
  for (const response of [
    () => Response.json({ jsonrpc: "2.0", id: 1, result: {} }, { status: 201 }),
    () => new Response("{}"),
    () => Response.json({ jsonrpc: "2.0", id: 2, result: {} }),
    () => Response.json([{ jsonrpc: "2.0", id: 1, result: {} }]),
    () =>
      Response.json({
        jsonrpc: "2.0",
        id: 1,
        result: {},
        error: { code: -1, message: "bad" },
      }),
  ]) {
    const transport = new BackendTransport(
      backend({ type: "http", url: "https://backend.test" }),
      async () => response(),
    );
    try {
      await assert.rejects(transport.request(request()));
    } finally {
      await transport.close();
    }
  }
  const transport = new BackendTransport(
    backend({ type: "http", url: "https://backend.test" }),
    async () => new Response("body", { status: 202 }),
  );
  try {
    await assert.rejects(transport.notify(notification));
  } finally {
    await transport.close();
  }
});

test(
  "persistent stdio reuses one process and serializes requests and notifications",
  { timeout: 5000 },
  async () => {
    const transport = stdio(echo);
    try {
      const first = transport.request(request(1));
      const observed = transport.notify(notification);
      const second = transport.request(request(2));
      const [a, , b] = await Promise.all([first, observed, second]);
      assert.equal(a.result.pid, b.result.pid);
      assert.equal(a.result.count, 1);
      assert.equal(b.result.count, 3);
      await transport.close();
      assert.throws(() => process.kill(a.result.pid, 0), { code: "ESRCH" });
      await assert.rejects(transport.request(request(3)), /closed/);
      await transport.close();
    } finally {
      await transport.close();
    }
  },
);

test(
  "per-event stdio sends EOF and starts a new process for each message",
  { timeout: 5000 },
  async () => {
    const transport = stdio(
      `let input='';process.stdin.on('data', c => input+=c);process.stdin.on('end',()=>{
    const m=JSON.parse(input); if ('id' in m) console.log(JSON.stringify({jsonrpc:'2.0',id:m.id,result:process.pid}));
  });`,
      "per_event",
    );
    try {
      const a = await transport.request(request(1));
      const b = await transport.request(request(2));
      assert.notEqual(a.result, b.result);
      assert.throws(() => process.kill(a.result, 0), { code: "ESRCH" });
      await transport.notify(notification);
    } finally {
      await transport.close();
    }
  },
);

test(
  "stdio rejects malformed framing, extra responses and unsuccessful per-event exits",
  { timeout: 5000 },
  async () => {
    for (const code of [
      `process.stdin.resume();process.stdout.write('not json\\n');`,
      `process.stdin.resume();process.stdout.write(Buffer.from([255,10]));`,
      `process.stdin.resume();process.stdout.write('{}');process.exit(0);`,
      `process.stdin.resume();console.log(JSON.stringify({jsonrpc:'2.0',id:99,result:{}}));`,
      `process.stdin.resume();console.log(JSON.stringify({jsonrpc:'2.0',id:1,result:{}}));process.exit(2);`,
      `process.stdin.resume();const s=JSON.stringify({jsonrpc:'2.0',id:1,result:{}})+'\\n';process.stdout.write(s+s);process.exit(0);`,
    ]) {
      const transport = stdio(code, "per_event");
      try {
        await assert.rejects(
          transport.request(request(), AbortSignal.timeout(1000)),
        );
      } finally {
        await transport.close();
      }
    }
  },
);

test(
  "cancellation restarts persistent processes and pre-dispatch cancellation sends nothing",
  { timeout: 5000 },
  async () => {
    const transport = stdio(
      echo.replace("if ('id' in m)", "if ('id' in m && m.id !== 'hang')"),
    );
    try {
      const first = await transport.request(request());
      const pending = transport.request(
        request("hang"),
        AbortSignal.timeout(100),
      );
      const controller = new AbortController();
      const queued = transport.request(request(2), controller.signal);
      controller.abort(new Error("queued cancellation"));
      await assert.rejects(queued, /queued cancellation/);
      await assert.rejects(pending, { name: "TimeoutError" });
      const next = await transport.request(request(3));
      assert.notEqual(first.result.pid, next.result.pid);
      assert.equal(next.result.count, 1);
    } finally {
      await transport.close();
    }
  },
);

test(
  "stdio decodes split UTF-8 frames and preserves JSON-RPC errors",
  { timeout: 5000 },
  async () => {
    const transport = stdio(`process.stdin.once('data',()=>{
    const data=Buffer.from(JSON.stringify({jsonrpc:'2.0',id:1,error:{code:-32601,message:'café'}})+'\\n');
    const split=data.indexOf(0xc3)+1;process.stdout.write(data.subarray(0,split));
    setTimeout(()=>process.stdout.write(data.subarray(split)),10);
  });`);
    try {
      assert.deepEqual((await transport.request(request())).error, {
        code: -32601,
        message: "café",
      });
    } finally {
      await transport.close();
    }
  },
);

test("pre-aborted HTTP requests never invoke authenticated fetch", async () => {
  let called = false;
  const transport = new BackendTransport(
    backend({ type: "http", url: "https://backend.test" }),
    async () => {
      called = true;
      return Response.json({});
    },
  );
  try {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(transport.request(request(), controller.signal), {
      name: "AbortError",
    });
    assert.equal(called, false);
  } finally {
    await transport.close();
  }
});

test(
  "close interrupts active stdio and HTTP requests and is idempotent",
  { timeout: 5000 },
  async () => {
    for (const transport of [
      stdio("process.stdin.resume();setInterval(()=>{},1000)"),
      new BackendTransport(
        backend({ type: "http", url: "https://backend.test" }),
        () => new Promise(() => {}),
      ),
    ]) {
      const pending = transport.request(request());
      const rejected = assert.rejects(pending, /closed/);
      const otherRejected = assert.rejects(
        transport.request(request(2)),
        /closed/,
      );
      await new Promise((resolve) => setTimeout(resolve, 20));
      const closing = transport.close();
      assert.equal(transport.close(), closing);
      await closing;
      await Promise.all([rejected, otherRejected]);
    }
  },
);

test(
  "persistent stdio serializes intercepts and correlates typed IDs",
  { timeout: 5000 },
  async () => {
    const transport = stdio(`
      let active = false;
      require('node:readline').createInterface({input: process.stdin}).on('line', line => {
        const m = JSON.parse(line);
        if (active) process.exit(2);
        active = true;
        setTimeout(() => {
          active = false;
          console.log(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{request:m.id,pid:process.pid}}));
        }, 50);
      });
    `);
    try {
      const completed = [];
      const send = (id) =>
        transport
          .request({ ...request(id), method: "hooks/intercept" })
          .then((value) => {
            completed.push(value.id);
            return value;
          });
      const [first, second] = await Promise.all([send(1), send("1")]);
      assert.deepEqual(completed, [1, "1"]);
      assert.equal(first.result.request, 1);
      assert.equal(second.result.request, "1");
      assert.equal(first.result.pid, second.result.pid);
    } finally {
      await transport.close();
    }
  },
);

test(
  "cancelling an active persistent intercept reaps it before the queued call starts",
  { timeout: 5000 },
  async () => {
    const { mkdtemp, readFile, rm } = await import("node:fs/promises");
    const dir = await mkdtemp("/tmp/ahp-serialized-");
    const path = dir + "/pid";
    const transport = stdio(`
      const fs = require('node:fs');
      require('node:readline').createInterface({input: process.stdin}).on('line', line => {
        const m = JSON.parse(line);
        if (m.id === 'A') {
          fs.writeFileSync(${JSON.stringify(path)}, String(process.pid));
          process.on('SIGTERM', () => {});
        } else {
          const old = Number(fs.readFileSync(${JSON.stringify(path)}, 'utf8'));
          let alive = true;
          try { process.kill(old, 0); } catch (e) { if (e.code === 'ESRCH') alive = false; else throw e; }
          console.log(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{alive,pid:process.pid,old}}));
        }
      });
    `);
    try {
      const controller = new AbortController();
      const a = transport.request(
        { ...request("A"), method: "hooks/intercept" },
        controller.signal,
      );
      const rejected = assert.rejects(a, /cancel A/);
      const b = transport.request({
        ...request("B"),
        method: "hooks/intercept",
      });
      for (;;) {
        try {
          await readFile(path);
          break;
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      controller.abort(new Error("cancel A"));
      await rejected;
      const second = await b;
      assert.equal(second.id, "B");
      assert.equal(second.result.alive, false);
      assert.notEqual(second.result.pid, second.result.old);
      assert.equal(
        (await transport.request(request("C"))).result.pid,
        second.result.pid,
      );
    } finally {
      await transport.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
);
