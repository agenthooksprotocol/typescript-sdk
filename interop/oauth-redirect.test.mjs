import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { listen } from "./common.mjs";
import { accessToken, fixtureAuth, fixtureFetch } from "./security.mjs";
test("OAuth refuses redirects without forwarding client credentials to another origin", async () => {
  let leakedRequests = 0,
    issuerRequests = 0,
    status = 307;
  const target = createServer((req, res) => {
    leakedRequests++;
    req.resume();
    res.end(JSON.stringify({ access_token: "unexpected" }));
  });
  const targetEndpoint = await listen(target);
  const issuer = createServer(async (req, res) => {
    issuerRequests++;
    let data = "";
    for await (const chunk of req) data += chunk;
    assert.equal(
      new URLSearchParams(data).get("client_secret"),
      "TEST-ONLY-redirect-secret",
    );
    res.writeHead(status, { location: targetEndpoint + "/stolen" });
    res.end();
  });
  const endpoint = await listen(issuer);
  try {
    for (status of [301, 302, 303, 307, 308])
      await assert.rejects(() =>
        accessToken({
          mode: "oauth",
          tokenEndpoint: endpoint + "/token",
          clientId: "test",
          clientSecret: "TEST-ONLY-redirect-secret",
        }),
      );
    assert.equal(issuerRequests, 5);
    assert.equal(leakedRequests, 0);
  } finally {
    issuer.closeAllConnections();
    target.closeAllConnections();
    await Promise.all([
      new Promise((r) => issuer.close(r)),
      new Promise((r) => target.close(r)),
    ]);
  }
});

test("TLS fixture identity is never applied to upload or OAuth destinations", async () => {
  const received = [];
  const server = createServer((req, res) => {
    received.push(req.url);
    req.resume();
    res.end("ok");
  });
  const endpoint = await listen(server);
  try {
    // Nonexistent files prove that the TLS branch is not entered for other routes.
    const network = fixtureFetch(
      {
        mode: "mtls",
        caFile: "/missing-ca",
        certFile: "/missing-cert",
        keyFile: "/missing-key",
      },
      endpoint + "/hooks",
    );
    for (const path of ["/upload", "/token", "/hooks?other-binding=1"]) {
      const response = await network(endpoint + path);
      assert.equal(await response.text(), "ok");
    }
    assert.deepEqual(received, ["/upload", "/token", "/hooks?other-binding=1"]);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});

test("fixture auth keeps event credentials out of anonymous and separately authenticated uploads", async () => {
  const name = "AHP_TEST_ISOLATED_UPLOAD_TOKEN";
  const previous = process.env[name];
  process.env[name] = "TEST-ONLY-upload-token";
  try {
    const provider = fixtureAuth({
      mode: "bearer",
      token: "TEST-ONLY-event-token",
    });
    const url = "https://receiver.example/shared";
    assert.equal(
      (await provider.authenticate({ url, purpose: "event" })).token,
      "TEST-ONLY-event-token",
    );
    assert.equal(
      await provider.authenticate({ url, purpose: "upload" }),
      undefined,
    );
    assert.equal(
      (
        await provider.authenticate({
          url,
          purpose: "upload",
          authentication: {
            type: "bearer",
            tokenEnv: name,
          },
        })
      ).token,
      "TEST-ONLY-upload-token",
    );
    // Even a reference named like the fixture event source must not leak it.
    await assert.rejects(
      provider.authenticate({
        url,
        purpose: "upload",
        authentication: {
          type: "bearer",
          tokenRef: "fixture-token",
        },
      }),
    );
    for (const config of [
      { mode: "workload", assertion: "TEST-ONLY-workload-token" },
      {
        mode: "oauth",
        tokenEndpoint: "https://must-not-contact.invalid/token",
      },
    ])
      assert.equal(
        await fixtureAuth(config).authenticate({ url, purpose: "upload" }),
        undefined,
      );
  } finally {
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  }
});
