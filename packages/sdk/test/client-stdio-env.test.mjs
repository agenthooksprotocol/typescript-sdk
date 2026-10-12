import test from "node:test";
import assert from "node:assert/strict";
import { BackendTransport } from "agenthooksprotocol/client";
import { backendEnvironment } from "../dist/src/client/transport.js";

// The child echoes the variables the test inspects.
const echo = `require('node:readline').createInterface({input: process.stdin}).on('line', line => {
  const m = JSON.parse(line);
  const pick = n => process.env[n] ?? null;
  process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{
    hostOnly: pick('AHP_TEST_HOST_ONLY'), registered: pick('AHP_TEST_REGISTERED'),
    home: pick('HOME'), path: pick('PATH'),
  }})+'\\n');
});`;
const request = {
  jsonrpc: "2.0",
  id: 1,
  method: "hooks/capabilities",
  params: { protocolVersion: "draft" },
};
async function childEnv(env, options) {
  const transport = new BackendTransport(
    {
      id: "env.backend",
      subscriptions: [],
      transport: {
        type: "stdio",
        command: process.execPath,
        args: ["-e", echo],
        lifecycle: "persistent",
        ...(env === undefined ? {} : { env }),
      },
    },
    () => {
      throw new Error("stdio must not fetch");
    },
    options,
  );
  try {
    return (await transport.request(request)).result;
  } finally {
    await transport.close();
  }
}

test(
  "stdio backends get a minimal base environment plus registration env",
  { timeout: 5000 },
  async () => {
    process.env.AHP_TEST_HOST_ONLY = "host value";
    try {
      const result = await childEnv({
        AHP_TEST_REGISTERED: "$HOME literal",
        HOME: "/registered/home",
      });
      assert.equal(result.hostOnly, null);
      assert.equal(result.registered, "$HOME literal");
      assert.equal(result.home, "/registered/home");
      assert.equal(result.path, process.env.PATH ?? null);
      const plain = await childEnv(undefined);
      assert.equal(plain.hostOnly, null);
      assert.equal(plain.registered, null);
    } finally {
      delete process.env.AHP_TEST_HOST_ONLY;
    }
  },
);

test(
  "inheritEnvironment opts into the full host environment",
  { timeout: 5000 },
  async () => {
    process.env.AHP_TEST_HOST_ONLY = "host value";
    try {
      const result = await childEnv(
        { AHP_TEST_REGISTERED: "set" },
        { inheritEnvironment: true },
      );
      assert.equal(result.hostOnly, "host value");
      assert.equal(result.registered, "set");
    } finally {
      delete process.env.AHP_TEST_HOST_ONLY;
    }
  },
);

test("base allowlist covers locale and Windows names case-insensitively", () => {
  const host = {
    PATH: "/bin",
    LC_TIME: "C",
    SECRET_TOKEN: "x",
    Path: "C:\\Windows",
    SystemRoot: "C:\\Windows",
    UserProfile: "C:\\Users\\a",
  };
  assert.deepEqual(backendEnvironment(undefined, false, host, "linux"), {
    PATH: "/bin",
    LC_TIME: "C",
  });
  const windows = backendEnvironment(
    { PATH: "C:\\override" },
    false,
    host,
    "win32",
  );
  assert.deepEqual(windows, {
    LC_TIME: "C",
    SystemRoot: "C:\\Windows",
    UserProfile: "C:\\Users\\a",
    PATH: "C:\\override",
  });
  assert.deepEqual(backendEnvironment({ A: "1" }, true, host, "linux"), {
    ...host,
    A: "1",
  });
});
