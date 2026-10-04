// @ts-check
import {
  config,
  scenarios,
  atomic,
  fixtureRegistration,
  fixtureCapabilities,
  sdkClient,
  sdkDraft,
} from "./common.mjs";
import { readFile, rm, mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createContentAdapter,
  prepareRequestContent,
} from "./content-upload.mjs";
import { fixtureAuth, fixtureFetch } from "./security.mjs";
import { summarizeAccepted, matches } from "./evaluator.mjs";
const { Hooks, BackendTransport } = sdkClient;
const {
  validateInterceptRequest,
  validateCapabilitiesResponse,
  validateCapabilities,
} = sdkDraft;
const cfg = await config(),
  rows = await scenarios(cfg.scenarioFile),
  results = [];
const security = cfg.auth ?? { mode: "none" };
const unsupported = !["none", "bearer", "oauth", "workload", "mtls"].includes(
  security.mode,
);
const inapplicable = cfg.transport === "stdio" && security.mode !== "none";
/** @type {InstanceType<typeof Hooks> | undefined} */
let hooks;
/** @type {InstanceType<typeof BackendTransport> | undefined} */
let discoveryTransport;
/** @type {string | undefined} */
let batchDirectory;
try {
  if (unsupported || inapplicable) {
    for (const row of rows)
      results.push({
        id: row.id,
        status: inapplicable ? "inapplicable" : "unsupported",
        actual: null,
      });
  } else if (rows.length) {
    const registration = fixtureRegistration(cfg, rows);
    const provider = fixtureAuth(security);
    const backend = registration.hooks[0];
    const networkFetch = fixtureFetch(
      security,
      cfg.transport === "http"
        ? [
            new URL("/intercept", cfg.endpoint).href,
            new URL("/capabilities", cfg.endpoint).href,
          ]
        : [],
    );
    // Rows are serial, including observation completion. Keep one stable fetch
    // function on Hooks while routing each operation to its own source recorder.
    /** @type {ReturnType<typeof createContentAdapter> | undefined} */
    let activeContent;
    const capabilities = fixtureCapabilities(rows);
    let serverFixture;
    if (cfg.transport === "http") {
      // The canonical HTTP fixture binding exposes GET /capabilities.
      const url = new URL("/capabilities", cfg.endpoint).href;
      const credential = await provider.authenticate({
        url,
        purpose: "event",
        authentication: backend.authentication,
      });
      const response = await networkFetch(url, {
        redirect: "error",
        signal: AbortSignal.timeout(15000),
        headers: credential
          ? { authorization: `Bearer ${credential.token}` }
          : {},
      });
      if (!response.ok || !validateCapabilities(await response.json()).ok)
        throw Error("Invalid discovery capabilities");
    } else {
      serverFixture = JSON.parse(await readFile(cfg.serverConfig, "utf8"));
      discoveryTransport = new BackendTransport(backend, networkFetch);
      const request = {
        jsonrpc: "2.0",
        id: "discovery",
        method: "hooks/capabilities",
        params: { protocolVersion: "draft" },
      };
      const response = await discoveryTransport.request(
        request,
        AbortSignal.timeout(
          Math.max(15000, (serverFixture.watchdog ?? 15) * 1000),
        ),
      );
      const decoded = validateCapabilitiesResponse(response);
      if (!decoded.ok || decoded.value.id !== request.id)
        throw Error("Invalid discovery response");
      await discoveryTransport.close();
      discoveryTransport = undefined;
      if (serverFixture.readinessFile)
        await rm(serverFixture.readinessFile, { force: true });
      for (const row of rows)
        if (
          !decoded.value.result.manifest.events.some(
            (entry) =>
              entry.event === row.request.params.event.type &&
              entry.modes.includes("intercept"),
          )
        )
          throw Error("Unsupported event");
    }
    /** @type {import("@agenthooksprotocol/sdk/client").HooksOptions} */
    const options = {
      source: rows[0].request.params.event.source,
      capabilities,
      auth: provider,
      fetch: (input, init) =>
        activeContent
          ? activeContent.fetch(input, init)
          : networkFetch(input, init),
    };
    // A malformed stdio response correctly poisons an SDK process. Bound fixture
    // batches at negative cases so a relay snapshots actual receipts BEFORE that
    // response is forwarded. Restarting never invents or repairs a wire request.
    /** @type {Array<Array<import("./common.mjs").FixtureScenario>>} */
    const batches = [];
    let pending = [];
    for (const row of rows) {
      pending.push(row);
      if (cfg.transport === "stdio" && row.expectError) {
        batches.push(pending);
        pending = [];
      }
    }
    if (pending.length) batches.push(pending);
    const receipts = [];
    if (cfg.transport === "stdio")
      batchDirectory = await mkdtemp(join(tmpdir(), "ahp-sdk-batches-"));
    for (const [index, batch] of batches.entries()) {
      let batchConfig = cfg;
      let receiptFile;
      if (batchDirectory) {
        const scenarioFile = join(batchDirectory, `${index}-scenarios.json`);
        const serverConfig = join(batchDirectory, `${index}-server.json`);
        receiptFile = serverFixture.receiptFile
          ? join(batchDirectory, `${index}-receipts.json`)
          : undefined;
        await atomic(scenarioFile, { version: 1, scenarios: batch });
        await atomic(serverConfig, {
          ...serverFixture,
          scenarioFile,
          ...(receiptFile
            ? {
                receiptFile,
                readinessFile: join(batchDirectory, `${index}-ready.json`),
              }
            : {}),
        });
        if (!receiptFile && serverFixture.readinessFile)
          await rm(serverFixture.readinessFile, { force: true });
        batchConfig = { ...cfg, serverConfig };
      }
      const batchRegistration = fixtureRegistration(batchConfig, batch);
      const uploadEndpoints = batchRegistration.hooks.flatMap((hook) =>
        hook.subscriptions.flatMap((subscription) =>
          subscription.upload &&
          typeof subscription.upload === "object" &&
          "endpoint" in subscription.upload &&
          typeof subscription.upload.endpoint === "string"
            ? [subscription.upload.endpoint]
            : [],
        ),
      );
      hooks = new Hooks(batchRegistration, options);
      await hooks.initialized;
      try {
        for (const row of batch) {
          const contentSources = row.contentSources ?? cfg.contentSources;
          activeContent = undefined;
          try {
            if (contentSources !== undefined)
              activeContent = createContentAdapter(
                contentSources,
                networkFetch,
                uploadEndpoints,
              );
            if (!validateInterceptRequest(row.request).ok)
              throw Error("Invalid canonical request");
            const request = structuredClone(row.request);
            if (activeContent) activeContent.hydrate(request.params.event);
            else
              await prepareRequestContent(
                request,
                row.contentBodies,
                cfg,
                row.subscription,
              );
            const event = request.params.event;
            if (event.source !== options.source)
              throw Error("Inconsistent fixture source");
            // A validated canonical event is structurally a boundary input; Hooks
            // still owns/overwrites its source, type, version and occurrence ID.
            const result = await hooks.dispatch(event.type, event, {
              capabilities: row.request.params.capabilities,
              ...(row.request.params.state === undefined
                ? {}
                : { state: row.request.params.state }),
            });
            const observationErrors = await result.observations;
            if (
              result.errors.length ||
              observationErrors.length ||
              result.interrupted
            ) {
              if (
                row.expectError &&
                result.errors.some(
                  (error) =>
                    error.phase === "interception" &&
                    (error.code === "DELIVERY_FAILED" ||
                      (error.code === "DEADLINE_EXCEEDED" &&
                        row.response !== null &&
                        typeof row.response === "object" &&
                        "id" in row.response &&
                        (typeof row.response.id === "string" ||
                          typeof row.response.id === "number") &&
                        row.response.id !== row.request.id)),
                )
              ) {
                results.push({
                  id: row.id,
                  status: "passed",
                  actual: { rejected: true },
                });
                continue;
              }
              throw Error("SDK delivery failed");
            }
            const sdkActual = summarizeAccepted(row.request, result);
            // Fixture-only host rule, not an AHP input constraint. Preserve SDK
            // acceptance/effects and report host refusal as a separate layer.
            const hostRejected =
              result.event.type === "tool.before" &&
              result.event.tool.name === "task" &&
              !(
                Number.isInteger(result.event.tool.input.task) &&
                result.event.tool.input.task > 0
              );
            const actual = hostRejected
              ? { ...sdkActual, executed: false }
              : sdkActual;
            if (hostRejected) {
              results.push({
                id: row.id,
                status: row.expectError ? "passed" : "failed",
                actual,
                sdkAccepted: true,
                hostAccepted: false,
                rejectionLayer: "host-input-schema",
              });
              continue;
            }
            results.push({
              id: row.id,
              status:
                !row.expectError && matches(actual, row.expected ?? {})
                  ? "passed"
                  : "failed",
              actual,
            });
          } catch {
            results.push({
              id: row.id,
              status: "failed",
              actual: null,
              error: "Validation, transport, or effect application failed",
            });
          } finally {
            if (contentSources !== undefined) {
              const entry = results.at(-1);
              if (entry?.id === row.id)
                Object.assign(entry, {
                  contentUploads: activeContent?.contentUploads ?? [],
                });
            }
            activeContent = undefined;
          }
        }
        if (receiptFile) {
          const actualReceipts = JSON.parse(
            await readFile(receiptFile, "utf8"),
          );
          if (!Array.isArray(actualReceipts.requests))
            throw Error("Invalid relay receipts");
          receipts.push(...actualReceipts.requests);
          await atomic(serverFixture.receiptFile, { requests: receipts });
        }
      } finally {
        await hooks.close();
        hooks = undefined;
      }
    }
  }
} catch {
  process.exitCode = 1;
  for (const row of rows)
    if (!results.some((result) => result.id === row.id))
      results.push({
        id: row.id,
        status: "failed",
        actual: null,
        error: "Adapter setup failed",
      });
} finally {
  await discoveryTransport?.close();
  await hooks?.close();
  if (batchDirectory)
    await rm(batchDirectory, { recursive: true, force: true });
  await atomic(cfg.reportFile, { language: "typescript", results });
}
if (results.some((result) => result.status === "failed")) process.exitCode = 1;
