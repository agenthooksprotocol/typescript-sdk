import {
  _projectHostInput,
  ownedAttachment,
  hostCapabilitiesToWire,
  events,
  Permission,
  responseForRequest,
  PROTOCOL_VERSION,
} from "../draft/raw.js";
import type { BoundaryContracts, Codec } from "./contracts.js";
import { decodeSettledEvent, decodeSettledState, SettlementDecodeError } from "./settlement.js";
import { HookOperationalError } from "../errors.js";
import type {
  Authentication,
  ContentUpload,
  Configuration,
  Backend,
  Capabilities,
  Effect,
  InterceptResponse,
  InterceptSubscription,
  ObserveSubscription,
  Registration,
  StaticCapabilityManifest,
  WireCapabilities,
} from "../draft/raw.js";
import {
  validateCapabilities,
  validateInterceptRequest,
  validateInterceptResponse,
} from "../draft/index.js";
import { isPartPath, localParts, mapParts } from "./content-paths.js";
import { resolveHeaders, validateHeaders } from "./headers.js";
import { BackendTransport } from "./transport.js";
import { Attachment, ContentManager, UploadLimiter, createSharedContentManager } from "./content.js";
import { composeResponseAsync, normalizeEffects, type ComposedEffect } from "./composition.js";
import { runtimeInteger } from "../runtime-integer.js";
import { admitContracts, decodeContract, encodeContract, freezeContractValue, type ToolBeforeInput, type ToolBeforeResult } from "./contracts.js";
import { auth, classifyAuthError } from "./auth.js";
import { bearerParameters } from "./challenge.js";
import { isEventType, validateWire } from "./validation.js";
import {
  ConfigurationError,
  type BoundaryInput,
  type EventInput,
  type BoundaryOptions,
  type BoundaryResult,
  type Event,
  type EventType,
  type HooksOptions,
  type DeliveryDiagnostic,
  type DeliveryAuthFailure,
  type ConfigurationSkipCode,
  type InitializationDiagnostic,
} from "./types.js";

/** A backend skipped as `configuration_unavailable`, awaiting a re-attempt. */
type UnavailableBackend = {
  readonly index: number;
  readonly backend: Backend;
  /** Consecutive failed attempts since initialization or the last host prepare. */
  failures: number;
  /** Earliest backoff re-attempt; undefined when only a host prepare re-attempts. */
  retryAt: number | undefined;
  /** A successful host prepare for the event endpoint makes it eligible at once. */
  prepared: boolean;
};
/** Stored skip diagnostics per backend; older ones are dropped. */
const MAX_DIAGNOSTICS_PER_BACKEND = 10;
/** Compare endpoint URLs in their normalized form. */
function sameUrl(left: string, right: string): boolean {
  try { return new URL(left).href === new URL(right).href; } catch { return false; }
}
/** JSON-RPC method-not-found: the backend has no configuration advertisement. */
const METHOD_NOT_FOUND = -32601;

type DeliveryFailure = Omit<DeliveryDiagnostic, "code"> & {
  code: "PREPARATION_FAILED" | "DELIVERY_FAILED" | "DEADLINE_EXCEEDED" | "INTERRUPTED";
};
// The generated renderer guarantees canonical grant shapes. Detach its readonly
// data before mutable delivery snapshots; outer configuration admission remains
// authoritative. No serialization, JSON decoding, or generic builder is involved.
function ownedCapabilities(value: WireCapabilities): Capabilities {
  return structuredClone(value) as unknown as Capabilities;
}
/** Check supplied metadata fields only. Opaque extensions are not wire grants
 * or content, and must not be recursively interpreted as either. */
/** Whether an upload binding references a secret only a registration may name. */
function namesLocalSecret(binding: Authentication | undefined): boolean {
  return binding !== undefined && ["tokenEnv", "tokenRef", "clientSecretRef"].some(key => Object.hasOwn(binding, key));
}

function validateManifestMetadata(metadata: NonNullable<HooksOptions["manifestMetadata"]>): void {
  const invalid = (field: string): never => { throw new ConfigurationError([
    { path: `manifestMetadata.${field}`, code: "INVALID_CAPABILITIES" },
  ]); };
  const object = (value: unknown): value is Record<string, unknown> =>
    value !== null && typeof value === "object" && !Array.isArray(value);
  const strings = (value: unknown): boolean =>
    Array.isArray(value) && value.every(item => typeof item === "string");
  for (const field of ["authentication", "transports", "contentCategories", "correlationIdentityFields", "toolPaths"] as const)
    if (metadata[field] !== undefined && !strings(metadata[field])) invalid(field);
  if (metadata.managedPolicy !== undefined) {
    const policy = metadata.managedPolicy;
    if (!object(policy) || typeof policy.disableable !== "boolean" || !strings(policy.scopes))
      invalid("managedPolicy");
  }
  if (metadata.limits !== undefined) {
    const limits = metadata.limits;
    if (!object(limits)) return invalid("limits");
    for (const field of ["maxContinuations", "maxTimeoutMs", "maxUploadBytes", "minTimeoutMs"] as const) {
      const value = limits[field];
      if (value !== undefined && !(typeof value === "bigint" ? value >= 0n
        : typeof value === "number" && Number.isSafeInteger(value) && value >= 0))
        invalid(`limits.${field}`);
    }
  }
  if (metadata.gaps !== undefined && (!Array.isArray(metadata.gaps) ||
      !metadata.gaps.every(gap => object(gap) && typeof gap.path === "string" && typeof gap.reason === "string")))
    invalid("gaps");
}
type Subscription = InterceptSubscription | ObserveSubscription;
type Route = {
  backend: Backend;
  subscription: Subscription;
  index: number;
  transport: BackendTransport;
};
const REPLAYABLE: ReadonlySet<unknown> = new Set(["hooks/intercept", "hooks/configuration", "hooks/capabilities"]);
const eventTypes: readonly EventType[] = Object.values(events).filter(
  (event): event is EventType => typeof event === "string" && !event.includes("*"),
);
const matches = (selector: string, type: EventType) =>
  selector === "*" ||
  selector === type ||
  (selector.endsWith(".*") && selector.slice(0, -2) === type.split(".")[0]);

// Filters are exact optimization hints. Missing projections must never exclude
// an otherwise authorized route (notably tools whose kind is unknown).
function matchesFilters(subscription: Subscription, event: any): boolean {
  for (const [values, actual] of [
    [subscription.filters?.paths, event.path],
    [subscription.filters?.toolKinds, event.tool?.kind],
  ] as const) {
    if (Array.isArray(values) && typeof actual === "string" && !values.includes(actual)) return false;
  }
  return true;
}

type ElicitationLifetime = {
  id: string;
  sessionId: string | undefined;
  retired: boolean;
};

/** Configuration-driven, harness-facing AHP client. No host operation is executed. */
export class Hooks {
  readonly initialized: Promise<void>;
  /**
   * Sanitized configuration-discovery skips, appended in order: one per skipped
   * attempt, at initialization and at each later re-attempt. Available after
   * initialized settles. `auth` is present when endpoint authentication made the
   * configuration unavailable.
   */
  readonly initializationDiagnostics: InitializationDiagnostic[] = [];
  private readonly lifetime = new AbortController();
  private readonly options: HooksOptions;
  private readonly routes: Route[] = [];
  /** Routes per backend in registration order; `routes` is their atomic flattening. */
  private readonly groups: Route[][] = [];
  private readonly unavailable = new Map<string, UnavailableBackend>();
  /** The single shared admission re-attempting unavailable backends, while running. */
  private admission: Promise<void> | undefined;
  private unsubscribePrepared: (() => void) | undefined;
  /** Discovery-configured backends, for matching host prepares. */
  private readonly discovered = new Map<string, Backend>();
  /** Host prepares seen per backend, so one arriving during an attempt is not lost. */
  private readonly prepares = new Map<string, number>();
  /** Discovery attempts in flight; prepare notifications are needed only while > 0 or a backend is unavailable. */
  private attempts = 0;
  private readonly managers = new Set<ContentManager>();
  private readonly pending = new Set<Promise<unknown>>();
  private readonly provider;
  private readonly uploadLimiter: UploadLimiter;
  private readonly deliveryHeaders = new Map<string, ReturnType<typeof validateHeaders>>();
  private readonly authContexts = new Map<string, any>();
  private manifest!: StaticCapabilityManifest;
  private configured = false;
  private closed?: Promise<void>;
  private readonly elicitations = new Map<
    string,
    { event: any; size: number }
  >();
  private elicitationBytes = 0;
  // Tokens exist only for active calls, including preparation before any bytes
  // can be retained. Retirement invalidates those calls without tombstones.
  private readonly activeElicitations = new Set<ElicitationLifetime>();

  constructor(config: unknown, options: HooksOptions) {
    const harnessIssues = validateWire("common", options.harness, "/$defs/harness");
    if (harnessIssues.length)
      throw new ConfigurationError(harnessIssues.map(path => ({ path: `harness${path}`, code: "INVALID_HARNESS" })));
    if (options.maxConcurrentUploads !== undefined &&
        (!Number.isSafeInteger(options.maxConcurrentUploads) || options.maxConcurrentUploads <= 0))
      throw new ConfigurationError([{ path: "maxConcurrentUploads", code: "INVALID_LIMIT" }]);
    this.uploadLimiter = new UploadLimiter(options.maxConcurrentUploads);
    this.options = {
      ...options,
      harness: structuredClone(options.harness),
      capabilities: structuredClone(options.capabilities),
      ...(options.manifestMetadata === undefined ? {} : {
        manifestMetadata: structuredClone(options.manifestMetadata),
      }),
    };
    this.provider = options.auth ?? auth();
    // Explicit subscriptions retain synchronous routing and lazy transport setup.
    // Omitted subscriptions discover defaults during initialized, before dispatch.
    // Configuration failures retain the Promise contract.
    try {
      const discovery = this.initialize(config);
      this.configured = discovery === undefined;
      this.initialized = discovery === undefined ? Promise.resolve() : discovery.then(() => {
        this.configured = true;
      });
    } catch (error) {
      this.initialized = Promise.reject(error);
    }
    // An optional initialized wait must not cause an unhandled rejection.
    void this.initialized.catch(() => {});
  }

  /** Static subscription interest, not permission or a delivery guarantee.
   * Filters requiring occurrence data are deliberately not evaluated. */
  subscribes(event: EventType): boolean {
    return this.selects(event, ["intercept", "observe"]);
  }

  /** Whether any intercept subscription the host granted selects `event`.
   * Payload filters are not evaluated. */
  intercepts(event: EventType): boolean {
    return this.selects(event, ["intercept"]);
  }

  private selects(event: EventType, modes: readonly Subscription["mode"][]): boolean {
    if (!this.configured) return false;
    const advertised = this.manifest.events.find(entry => entry.event === event);
    return advertised !== undefined && this.routes.some(route =>
      modes.includes(route.subscription.mode) &&
      advertised.modes.includes(route.subscription.mode) &&
      route.subscription.events.some(selector => matches(selector, event)));
  }

  private initialize(config: unknown): Promise<void> | void {
    const issues = validateWire("registration", config).map((path) => ({
      path,
      code: "INVALID_REGISTRATION",
    }));
    const retry = this.options.configurationRetry;
    if (retry !== undefined) {
      const valid = (value: unknown) => value === undefined || (Number.isSafeInteger(value) && (value as number) > 0);
      if (!retry || typeof retry !== "object" || !valid(retry.initialDelayMs) || !valid(retry.maxDelayMs) ||
          (retry.initialDelayMs ?? 30_000) > (retry.maxDelayMs ?? 3_600_000))
        issues.push({ path: "configurationRetry", code: "INVALID_LIMIT" });
    }
    for (const key of ["maxContentBytes", "observationTimeoutMs", "maxConcurrentUploads", "configurationTimeoutMs"] as const) {
      const value = this.options[key];
      if (
        value !== undefined &&
        (!Number.isSafeInteger(value) ||
          value <= 0 ||
          ((key === "observationTimeoutMs" || key === "configurationTimeoutMs") && value > 2147483647))
      )
        issues.push({ path: key, code: "INVALID_LIMIT" });
    }
    if (!this.options.source || typeof this.options.source !== "string")
      issues.push({ path: "source", code: "INVALID_SOURCE" });
    if (issues.length) throw new ConfigurationError(issues);
    const registration = structuredClone(config) as Registration;
    const c = this.options.capabilities;
    if (!c || typeof c !== "object" || Array.isArray(c))
      throw new ConfigurationError([
        { path: "capabilities", code: "INVALID_CAPABILITIES" },
      ]);
    const metadata = this.options.manifestMetadata;
    if (metadata !== undefined &&
        (!metadata || typeof metadata !== "object" || Array.isArray(metadata) ||
         Object.hasOwn(metadata, "events")))
      throw new ConfigurationError([
        { path: "manifestMetadata", code: "INVALID_CAPABILITIES" },
      ]);
    if (metadata !== undefined) validateManifestMetadata(metadata);
    const declarations = hostCapabilitiesToWire(c);
    this.manifest = {
          authentication: ["bearer", "oauth"],
          contentCategories: [
            "text",
            "images",
            "audio",
            "video",
            "files",
            "reasoning",
          ],
          correlationIdentityFields: [
            "session.id",
            "turn.id",
            "call.id",
            "parentEventId",
          ],
          gaps: [],
          limits: {
            maxUploadBytes: this.options.maxContentBytes ?? 64 * 1024 * 1024,
          },
          managedPolicy: {
            disableable: false,
            scopes: ["user", "project", "managed"],
          },
          toolPaths: ["*"],
          transports: ["stdio", "http"],
          ...metadata,
          events: Object.entries(declarations).map(([event, declaration]) => ({
            event, modes: [...declaration.modes],
            ...(declaration.capabilities === undefined ? {} : {
              capabilities: ownedCapabilities(declaration.capabilities),
            }),
          })),
        };
    const ids = new Set<string>();
    for (const backend of registration.hooks) {
      if (ids.has(backend.id))
        issues.push({ path: backend.id, code: "DUPLICATE_BACKEND" });
      ids.add(backend.id);
      if (backend.transport.type === "http") {
        try {
          secureEndpoint(String(backend.transport.url));
        } catch {
          issues.push({ path: backend.id, code: "UNSAFE_ENDPOINT" });
        }
      }
      if (!["stdio", "http"].includes(backend.transport.type))
        issues.push({ path: backend.id, code: "UNSUPPORTED_TRANSPORT" });
      for (const [index, raw] of (backend.subscriptions ?? []).entries()) {
        const s = raw as Subscription;
        if (s.scope === "managed" && s.disableable !== false)
          issues.push({
            path: `${backend.id}.${index}`,
            code: "MANDATORY_SCOPE_DISABLEABLE",
          });
        if (s.scope && !this.manifest.managedPolicy.scopes.includes(s.scope))
          issues.push({
            path: `${backend.id}.${index}`,
            code: "UNSUPPORTED_SCOPE",
          });
        for (const selector of s.events) {
          if (!eventTypes.some((e) => matches(selector, e)))
            issues.push({
              path: `${backend.id}.${index}`,
              code: "UNSUPPORTED_EVENT",
            });
          if (
            !selector.includes("*") &&
            !this.manifest.events.some(
              (e) => e.event === selector && e.modes.includes(s.mode),
            )
          )
            issues.push({
              path: `${backend.id}.${index}`,
              code:
                s.mode === "intercept" ? "NOT_INTERCEPTABLE" : "NOT_OBSERVABLE",
            });
        }
      }
    }
    if (issues.length) throw new ConfigurationError(issues);
    const groups = this.groups;
    const discoveries: Promise<void>[] = [];
    for (const [position, backend] of registration.hooks.entries()) {
      this.deliveryHeaders.set(backend.id, backend.transport.type === "http"
        ? validateHeaders(backend.transport.headers) : []);
      const group: Route[] = [];
      groups.push(group);
      if (backend.subscriptions !== undefined) {
        const transport = this.transportFor(backend);
        (backend.subscriptions as Subscription[]).forEach((subscription, index) =>
          group.push({ backend, subscription, index, transport }));
      } else {
        this.discovered.set(backend.id, backend);
        discoveries.push(this.discoverRoutes(position, backend).then(routes => { group.push(...routes); }));
      }
    }
    const install = () => { this.routes.push(...groups.flat()); };
    if (!discoveries.length) return install();
    return Promise.allSettled(discoveries).then(async results => {
      const failed = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
      if (failed || this.lifetime.signal.aborted) {
        // Closed during initialization: routes that were discovered are never installed.
        await Promise.allSettled(groups.flat().map(route => route.transport.close()));
        throw failed ? failed.reason : this.lifetime.signal.reason;
      }
      install();
      this.syncPrepared();
    });
  }

  /** Subscribe to host prepares only while an attempt is in flight or a backend is unavailable,
   * so an unclosed client is not kept referenced by a long-lived provider. */
  private syncPrepared(): void {
    const wanted = !this.lifetime.signal.aborted && (this.attempts > 0 || this.unavailable.size > 0);
    if (wanted && !this.unsubscribePrepared && typeof this.provider.onPrepared === "function") {
      try {
        this.unsubscribePrepared = this.provider.onPrepared(endpoint => this.prepared(endpoint));
      } catch { /* A provider without working notifications only loses prepare re-attempts. */ }
    } else if (!wanted && this.unsubscribePrepared) {
      const unsubscribe = this.unsubscribePrepared;
      this.unsubscribePrepared = undefined;
      try { unsubscribe(); } catch { /* Best effort. */ }
    }
  }

  private transportFor(backend: Backend): BackendTransport {
    // Hooks resolves headers at the shared event/upload delivery boundary.
    const transportBackend = structuredClone(backend);
    if (transportBackend.transport.type === "http") delete transportBackend.transport.headers;
    return new BackendTransport(transportBackend, (url, init) =>
      this.fetchAuthenticated(
        url,
        init,
        backend.authentication,
        "event",
        backend.id,
      ),
      {
        inheritEnvironment: this.options.inheritEnvironment === true,
        ...(this.options.spawn ? { spawn: this.options.spawn } : {}),
        ...(this.options.environment ? { environment: this.options.environment } : {}),
      },
    );
  }

  /** Discover one backend's routes with a fresh transport; a skip yields none. */
  private async discoverRoutes(position: number, backend: Backend): Promise<Route[]> {
    const transport = this.transportFor(backend);
    this.attempts++;
    this.syncPrepared();
    const preparesBefore = this.prepares.get(backend.id) ?? 0;
    try {
      const subscriptions = await this.discoverConfiguration(position, backend, transport, preparesBefore);
      return subscriptions.map((subscription, index) => ({ backend, subscription, index, transport }));
    } finally {
      this.attempts--;
    }
  }

  /** Record a skip. Only `configuration_unavailable` is re-attempted before reinitialization. */
  private skip(position: number, backend: Backend, code: ConfigurationSkipCode, failure?: DeliveryAuthFailure,
    preparesBefore = this.prepares.get(backend.id) ?? 0): void {
    this.initializationDiagnostics.push({ backendId: backend.id, code, ...(failure ? { auth: failure } : {}) });
    // Keep only the latest diagnostics per backend.
    const own = this.initializationDiagnostics.flatMap((diagnostic, index) => diagnostic.backendId === backend.id ? [index] : []);
    if (own.length > MAX_DIAGNOSTICS_PER_BACKEND) this.initializationDiagnostics.splice(own[0]!, 1);
    if (code !== "configuration_unavailable") {
      this.unavailable.delete(backend.id);
      return;
    }
    // A host prepare during this attempt makes the backend eligible at once and resets its backoff.
    const prepared = (this.prepares.get(backend.id) ?? 0) !== preparesBefore;
    const failures = (prepared ? 0 : this.unavailable.get(backend.id)?.failures ?? 0) + 1;
    // Backoff only when there is no auth error or its recovery is retry: login,
    // configure and none need a host prepare (or reinitialization) first.
    const backoff = failure === undefined || failure.recovery === "retry";
    const initial = this.options.configurationRetry?.initialDelayMs ?? 30_000;
    const maximum = this.options.configurationRetry?.maxDelayMs ?? 3_600_000;
    const delay = Math.min(maximum, initial * 2 ** Math.min(failures - 1, 52));
    this.unavailable.set(backend.id, {
      index: position, backend, failures, prepared,
      retryAt: backoff ? Date.now() + delay : undefined,
    });
  }

  /** A successful host prepare for a skipped backend's event endpoint resets its backoff. */
  private prepared(endpoint: unknown): void {
    if (this.lifetime.signal.aborted || typeof endpoint !== "object" || endpoint === null) return;
    const { backendId, purpose, url } = endpoint as Partial<Record<"backendId" | "purpose" | "url", unknown>>;
    if (purpose !== "event" || typeof backendId !== "string" || typeof url !== "string") return;
    const backend = this.discovered.get(backendId);
    if (!backend || backend.transport.type !== "http" || !sameUrl(String(backend.transport.url), url)) return;
    this.prepares.set(backendId, (this.prepares.get(backendId) ?? 0) + 1);
    const entry = this.unavailable.get(backendId);
    if (!entry) return;
    entry.prepared = true;
    entry.failures = 0;
  }

  /**
   * The single shared admission: re-attempt due unavailable backends, then install
   * every newly discovered route set in one synchronous step. Concurrent callers
   * wait for the same operation, so none observes a partial route set; events
   * admitted earlier are never replayed.
   */
  private admit(): Promise<void> {
    if (this.admission) return this.admission;
    const now = Date.now();
    const due = [...this.unavailable.values()].filter(entry =>
      entry.prepared || (entry.retryAt !== undefined && now >= entry.retryAt));
    if (!due.length) return Promise.resolve();
    for (const entry of due) entry.prepared = false;
    const work = (async () => {
      const results = await Promise.allSettled(due.map(async entry =>
        [entry, await this.discoverRoutes(entry.index, entry.backend)] as const));
      const discovered = results.flatMap(result => result.status === "fulfilled" ? [result.value] : []);
      const failed = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
      if (failed || this.lifetime.signal.aborted) {
        // Closed during the re-attempt: close transports that will never be installed.
        await Promise.allSettled(discovered.flatMap(([, routes]) => routes.map(route => route.transport.close())));
        throw failed ? failed.reason : this.lifetime.signal.reason;
      }
      let changed = false;
      for (const [entry, routes] of discovered) {
        if (!routes.length) continue;
        this.unavailable.delete(entry.backend.id);
        this.groups[entry.index] = routes;
        changed = true;
      }
      if (changed) this.routes.splice(0, this.routes.length, ...this.groups.flat());
    })().finally(() => { this.admission = undefined; this.syncPrepared(); });
    this.admission = work;
    return work;
  }

  private async discoverConfiguration(position: number, backend: Backend, transport: BackendTransport,
    preparesBefore: number): Promise<Subscription[]> {
    const skip = (code: ConfigurationSkipCode, failure?: DeliveryAuthFailure) =>
      this.skip(position, backend, code, failure, preparesBefore);
    const budget = deadlineAfter(this.options.configurationTimeoutMs ?? 5000, this.lifetime.signal);
    let retained = false;
    try {
      const response = await transport.request({
        jsonrpc: "2.0", id: crypto.randomUUID(), method: "hooks/configuration",
        params: { protocolVersion: PROTOCOL_VERSION },
      }, budget.signal);
      budget.check();
      const rpcError = (response as { error?: { code?: unknown } }).error;
      if (rpcError !== undefined) {
        // Method-not-found means no advertisement; any other JSON-RPC error is unavailable.
        skip(rpcError.code === METHOD_NOT_FOUND ? "configuration_invalid" : "configuration_unavailable");
        return [];
      }
      if (validateWire("configuration-response", response).length) {
        skip("configuration_invalid");
        return [];
      }
      const configuration = (response as { result: { configuration: Configuration } }).result.configuration;
      // A server may pick its upload destination, not which local secret is read.
      if (configuration.subscriptions.some(subscription => namesLocalSecret((subscription.upload as ContentUpload | undefined)?.auth))) {
        skip("configuration_local_secret");
        return [];
      }
      const subscriptions = (configuration.subscriptions as Subscription[]).flatMap(subscription => {
        const selected = this.manifest.events.filter(event =>
          isEventType(event.event) && event.modes.includes(subscription.mode) &&
          subscription.events.some(selector => matches(selector, event.event as EventType)));
        return selected.length ? [{ ...subscription, events: selected.map(event => event.event) } as Subscription] : [];
      });
      if (!subscriptions.length) {
        skip("no_applicable_subscriptions");
        return [];
      }
      retained = true;
      return subscriptions;
    } catch (error) {
      // Cancellation propagates and emits no skip diagnostic.
      if (this.lifetime.signal.aborted) throw error;
      const auth = authFailure(error);
      // Uncorrelated or malformed responses are invalid; transport, timeout, HTTP
      // status and authentication failures are unavailable.
      const invalid = auth === undefined && error instanceof HookOperationalError &&
        (error.code === "MALFORMED_JSON_RPC" || error.code === "ID_MISMATCH" || error.code === "MALFORMED_JSON");
      skip(invalid ? "configuration_invalid" : "configuration_unavailable", auth);
      return [];
    } finally {
      budget.dispose();
      if (!retained) await transport.close();
    }
  }

  // Each endpoint binding has its own provider context; upload auth never inherits
  // event auth. Contexts belong to this Hooks instance, even with a shared provider.
  private async fetchAuthenticated(
    url: string,
    init: RequestInit,
    authentication: Authentication | undefined,
    purpose: "event" | "upload",
    backendId: string,
  ): Promise<Response> {
    secureEndpoint(url);
    const signal = init.signal ?? this.lifetime.signal;
    signal.throwIfAborted();
    const key = JSON.stringify([
      backendId,
      purpose,
      url,
      authentication ?? null,
    ]);
    let context = this.authContexts.get(key);
    if (!context) {
      context = {
        url,
        backendId,
        purpose,
        ...(authentication ? { authentication } : {}),
        cache: new Map(),
      };
      this.authContexts.set(key, context);
    }
    // Challenge state belongs to this delivery attempt, never another caller.
    context = { ...context };
    const entries = this.deliveryHeaders.get(backendId) ?? [];
    const configured = entries.length > 0
      ? await raceAbort(resolveHeaders(entries, this.provider, { ...context, signal }), signal)
      : new Headers();
    const explicitAuthorization = configured.has("authorization");
    // Challenged replay: after the provider handles a 401 or Bearer 403
    // insufficient_scope, replay once with the same id and buffered body, only
    // for requests that expect a response. Notifications and uploads are never
    // replayed; they rely on credentials sent on the first attempt.
    let replaySafe = false;
    if (purpose === "event" && typeof init.body === "string") {
      try {
        const message: unknown = JSON.parse(init.body);
        replaySafe = typeof message === "object" && message !== null &&
          REPLAYABLE.has((message as { method?: unknown }).method) &&
          Object.hasOwn(message, "id");
      } catch { /* Unknown request bodies are never replayed. */ }
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      const credential = explicitAuthorization ? undefined : await raceAbort(
        Promise.resolve(
          this.provider.credential({ ...context, signal }),
        ),
        signal,
      );
      if (
        !explicitAuthorization && !credential &&
        (authentication !== undefined || context.challenged === true)
      )
        throw new Error("Authentication credential required");
      const headers = new Headers(init.headers);
      headers.delete("authorization");
      if (credential) {
        if (
          typeof credential.token !== "string" ||
          !credential.token ||
          /[\s\x00-\x1f\x7f]/.test(credential.token) ||
          credential.type !== "bearer"
        )
          throw new Error("Invalid authentication credential");
        headers.set("authorization", `Bearer ${credential.token}`);
      }
      configured.forEach((value, name) => headers.set(name, value));
      const response = await raceAbort(
        (this.options.fetch ?? fetch)(url, {
          ...init,
          headers,
          redirect: "error",
          signal,
        }).then((response) => {
          if (signal.aborted) {
            void response.body?.cancel().catch(() => {});
            signal.throwIfAborted();
          }
          return response;
        }),
        signal,
      );
      let authRejected = response.status === 401;
      if (!explicitAuthorization && response.status === 403) {
        try {
          authRejected = bearerParameters(response.headers.get("www-authenticate") ?? undefined).get("error") === "insufficient_scope";
        } catch { /* Malformed/ambiguous challenges do not authorize retry. */ }
      }
      if (authRejected && !explicitAuthorization) {
        try {
          await raceAbort(
            Promise.resolve(
              this.provider.challenge({
                ...context,
                signal,
                response,
                credential,
              }),
            ),
            signal,
          );
        } catch (error) {
          void response.body?.cancel().catch(() => {});
          throw error;
        }
      }
      if (explicitAuthorization || !authRejected || !replaySafe || attempt === 1) return response;
      context.challenged = true;
      context.challenge = response.headers.get("www-authenticate") ?? undefined;
      void response.body?.cancel().catch(() => {});
    }
    throw new Error("Authentication failed");
  }

  /** Generic typed boundary dispatch; named methods below cover the complete catalogue. */
  async dispatch<K extends EventType>(
    type: K,
    input: BoundaryInput<K>,
    options: BoundaryOptions = {},
  ): Promise<BoundaryResult<K>> {
    const manager = createSharedContentManager({
      // Invalid configuration still transfers unused-source cleanup ownership;
      // initialize rejects it before any preparation can use this fallback.
      maxSnapshotBytes:
        Number.isSafeInteger(this.options.maxContentBytes) &&
        this.options.maxContentBytes! > 0
          ? this.options.maxContentBytes!
          : 64 * 1024 * 1024,
      allowLoopback: true,
    }, this.uploadLimiter);
    try {
      manager.own([localParts({ ...input, type }).map(({ part }) => part?.body), options.contentSources?.map(binding => binding.source)]);
    } catch (error) {
      await manager.close().catch(() => {});
      throw error;
    }
    this.managers.add(manager);
    const signal = combineSignals(this.lifetime.signal, options.signal);
    const exchange: ElicitationLifetime | undefined =
      type === "user.elicitation.request"
        ? {
            id: input.id === undefined ? crypto.randomUUID() : input.id,
            sessionId: (input as any).session?.id,
            retired: false,
          }
        : undefined;
    if (exchange) this.activeElicitations.add(exchange);
    let completed = false;
    let returnedContent: BoundaryResult<K>["content"];

    const work = (async () => {
      // Calls after close are misuse. Active calls return interruption evidence.
      this.lifetime.signal.throwIfAborted();
      await this.initialized;
      // Re-attempt due skipped backends inside the single shared admission. A
      // cancelled caller stops waiting; run() then reports the interruption.
      await raceAbort(this.admit(), signal).catch(error => { if (!signal.aborted) throw error; });
      return this.run(type, input, options, signal, manager, exchange);
    })();
    this.pending.add(work);
    try {
      const result = await work;
      completed = true;
      if (result.content && !result.interrupted) {
        manager.transfer(result.content);
        returnedContent = result.content;
      }
      return result;
    } catch (error) {
      if (error instanceof SettlementDecodeError && error.canonicalState === undefined)
        throw new SettlementDecodeError(error.message, error.acceptedResponses,
          freezeContractValue(structuredClone(options.initialState)), { cause: error });
      throw error;
    } finally {
      // Terminal exchanges retire even when validation or cancellation bypasses run.
      if (type === "user.elicitation.result")
        this.forgetElicitation((input as any).parentEventId);
      if (
        type === "user.elicitation.request" &&
        (!completed || signal.aborted) &&
        input.id
      )
        this.forgetElicitation(input.id);
      if (type === "session.end")
        this.retireSessionElicitations((input as any).session?.id);
      if (exchange) this.activeElicitations.delete(exchange);
      try {
        if (completed) await manager.close();
        else await manager.close().catch(() => {});
      } catch (error) {
        await returnedContent?.close().catch(() => {});
        throw error;
      } finally {
        this.managers.delete(manager);
        this.pending.delete(work);
      }
    }
  }

  private async run<K extends EventType>(
    type: K,
    input: BoundaryInput<K>,
    options: BoundaryOptions,
    signal: AbortSignal,
    manager: ContentManager,
    exchange?: ElicitationLifetime,
  ): Promise<BoundaryResult<K>> {
    const suppliedHarness = (input as { harness?: unknown }).harness;
    if (suppliedHarness !== undefined) {
      const issues = validateWire("common", suppliedHarness, "/$defs/harness");
      const supplied = suppliedHarness as HooksOptions["harness"];
      if (issues.length || supplied.name !== this.options.harness.name || supplied.version !== this.options.harness.version)
        throw new ConfigurationError([{ path: "harness", code: "INVALID_HARNESS" }]);
    }
    let event: any = cloneInput({
      ...input,
      type,
      source: this.options.source,
      harness: structuredClone(this.options.harness),
      id: exchange?.id ?? (input.id === undefined ? crypto.randomUUID() : input.id),
      time: input.time === undefined ? new Date().toISOString() : input.time,
    });
    bindContentSources(type, event, options.contentSources);
    if (type === "session.start")
      event.manifest = structuredClone(this.manifest);
    const requestId = event.id;
    // Project actual settled state, never replay cumulative effects: that would
    // duplicate injections/instructions and lose candidate invalidation.
    const snapshotState = (
      value: BoundaryOptions["initialState"],
    ): BoundaryResult<K>["state"] => {
      const snapshot = structuredClone(decodeSettledState(decodeSettledEvent(event), value));
      if (
        !Object.values(Permission).includes(snapshot.permission as Permission)
      )
        throw new ConfigurationError([
          { path: "initialState.permission", code: "INVALID_BOUNDARY_STATE" },
        ]);
      const freeze = (value: unknown): void => {
        if (value !== null && typeof value === "object") {
          for (const child of Object.values(value)) freeze(child);
          Object.freeze(value);
        }
      };
      freeze(snapshot);
      return snapshot as BoundaryResult<K>["state"];
    };
    if (signal.aborted) {
      const decodedEvent = decodeSettledEvent<K>(event);
      const decodedState = snapshotState(options.initialState);
      try { admitContracts(options.contracts, decodedEvent, decodedState as BoundaryOptions["initialState"]); }
      catch (cause) { throw new SettlementDecodeError("Interrupted boundary contract admission failed", [], decodedState, { cause }); }
      return {
        event: decodedEvent,
        effects: Object.freeze([]) as unknown as BoundaryResult<K>["effects"],
        acceptedResponses: [],
        state: decodedState,
        diagnostics: [],
        interrupted: true,
      } as BoundaryResult<K>;
    }
    let correlation: { event: Event; release: () => Promise<void> } | undefined;
    let originalRequest: Event | undefined;

    const acceptedResponses: BoundaryResult<K>["acceptedResponses"][number][] = [];
    let effects: ComposedEffect[] = [];
    let state = structuredClone(options.initialState);
    // A supplied snapshot is input to the first receiver, not a newly accepted
    // result in this chain. Composition settles terminal state after acceptance.
    let shortCircuit = false;
    let interrupted = false;
    const errors: DeliveryFailure[] = [];
    const advertised = this.manifest.events.find((e) => e.event === type);
    if (!advertised)
      throw new ConfigurationError([
        { path: type, code: "UNADVERTISED_EVENT" },
      ]);
    const staticCaps = advertised.capabilities ?? { effects: [] };
    const caps: Capabilities = structuredClone(
      options.capabilities ?? staticCaps,
    );
    // Reject widening before deriving occurrence counters or clamping budgets.
    if ((options.capabilities !== undefined && !validateCapabilities(caps).ok) ||
        !isNarrower(caps, staticCaps))
      throw new ConfigurationError([
        { path: type, code: "INVALID_CAPABILITY_NARROWING" },
      ]);
    if (type === "turn.finish.before" && caps.flow) {
      caps.flow.continuationCount = event.continuationCount;
      if (caps.flow.maxContinuations !== undefined)
        caps.flow.remainingContinuations = clampContinuations(
          caps.flow.remainingContinuations ?? 0,
          caps.flow.maxContinuations,
          event.continuationCount,
        );
    }
    if (
      !isNarrower(caps, staticCaps)
    )
      throw new ConfigurationError([
        { path: type, code: "INVALID_CAPABILITY_NARROWING" },
      ]);
    const called = new Set<Route>();
    const matching = this.routes.filter(
      (r) =>
        r.subscription.events.some((s) => matches(s, type)) &&
        advertised.modes.includes(r.subscription.mode) &&
        matchesFilters(r.subscription, event),
    );
    try {
      decodeSettledEvent<K>(event);
      admitContracts(options.contracts, event, state);
      correlation = this.elicitationFor(event);
      originalRequest = correlation?.event;
      // Validate a metadata-only view before any delivery (this does not consume bytes).
      const metadata = await manager.prepare(
        event,
        { default: "metadata" },
        undefined,
        () => Promise.reject(new Error("Unexpected upload")),
        signal,
      );
      const invalid = validateWire("observe-notification", {
        jsonrpc: "2.0",
        method: "hooks/observe",
        params: { protocolVersion: "draft", event: metadata },
      });
      if (invalid.length)
        throw new ConfigurationError(
          invalid.map((path) => ({ path, code: "INVALID_EVENT" })),
        );
      const invalidState =
        state === undefined
          ? []
          : validateWire("intercept-request", {
              jsonrpc: "2.0",
              id: requestId,
              method: "hooks/intercept",
              params: {
                protocolVersion: "draft",
                event: metadata,
                capabilities: caps,
                ...(state !== undefined ? { state } : {}),
              },
            });
      if (invalidState.length)
        throw new ConfigurationError(
          invalidState.map((path) => ({
            path,
            code: "INVALID_BOUNDARY_STATE",
          })),
        );
      // Plan from the admitted input, before any serial receiver can remove or
      // reorder attachments. Failures remain local until that route is delivered.
      const preparationFailures = new Map<Route, unknown>();
      await Promise.all(matching.map(async route => {
        const s = route.subscription;
        const budget = s.mode === "observe"
          ? deadlineAfter(this.options.observationTimeoutMs ?? 15000, signal) : undefined;
        const preparationSignal = budget?.signal ?? signal;
        try {
          await raceAbort(manager.prepare(
            projectNative(event, s.includeNative), s.content, s.upload,
            (url, init, upload) => this.fetchAuthenticated(url, init, upload.auth, "upload", route.backend.id),
            preparationSignal, route,
          ), preparationSignal);
        } catch (cause) { preparationFailures.set(route, cause); }
        finally { budget?.dispose(); }
      }));
      manager.finishPlanning();
      for (const route of matching) {
        if (route.subscription.mode !== "intercept" || shortCircuit) continue;
        if (signal.aborted && !preparationFailures.has(route)) {
          interrupted = true;
          break;
        }
        called.add(route);
        const s = route.subscription;
        let phase: DeliveryFailure["phase"] = "preparation";
        let deadline: AbortSignal | undefined;
        let received = false;
        let budget: ReturnType<typeof deadlineAfter> | undefined;
        try {
          if (preparationFailures.has(route)) throw preparationFailures.get(route);
          const projected = await raceAbort(
            manager.prepare(
              projectNative(event, s.includeNative),
              s.content,
              s.upload,
              (url, init, upload) =>
                this.fetchAuthenticated(
                  url,
                  init,
                  upload.auth,
                  "upload",
                  route.backend.id,
                ),
              signal,
              route,
            ),
            signal,
          );
          if (
            type === "user.elicitation.request" &&
            projected.elicitation?.request?.selection === "body" &&
            typeof event.elicitation?.request?.text === "string"
          ) {
            const size = new TextEncoder().encode(event.elicitation.request.text).byteLength;
            this.rememberElicitation(event, size, exchange!);
          }
          const request = {
            jsonrpc: "2.0",
            id: requestId,
            method: "hooks/intercept",
            params: {
              protocolVersion: "draft",
              event: projected,
              capabilities: caps,
              ...(state ? { state } : {}),
            },
          };
          const valid = validateInterceptRequest(request);
          if (!valid.ok) throw new Error("Invalid interception request");
          phase = "interception";
          budget = deadlineAfter(runtimeInteger(s.timeoutMs, 1), signal);
          deadline = budget.signal;
          const reply = await route.transport.request(valid.value, deadline);
          received = true;
          budget.check();
          if (reply && typeof reply === "object" && "error" in reply)
            throw new HookOperationalError(
              "JSON_RPC_ERROR",
              "Backend returned a JSON-RPC error",
            );
          const canonicalResponse = validateInterceptResponse(reply);
          const decoded = responseForRequest(type, reply);
          if (!canonicalResponse.ok || !decoded.ok || decoded.value.id !== requestId)
            throw new Error("Invalid interception response");
          // Elicitation terminals are mutually exclusive. Check the raw reply
          // before generic composition normalizes return + deny to denial.
          if (
            type === "user.elicitation.request" &&
            (decoded.value.result.effects ?? []).some(
              (effect) => effect.type === "return",
            ) &&
            (decoded.value.result.effects ?? []).some(
              (effect) => effect.type === "deny",
            )
          )
            throw new Error("Conflicting elicitation terminal effects");
          if (
            type === "user.elicitation.request" &&
            (decoded.value.result.effects ?? []).some(
              (effect) => effect.type === "return" || effect.type === "deny",
            ) &&
            (projected.elicitation?.request?.selection !== "body" ||
              typeof projected.elicitation.request.text !== "string" ||
              projected.elicitation.request.gap !== undefined)
          )
            throw new Error(
              "Elicitation terminals require selected request body",
            );
          const staged = await raceAbort(
            composeResponseAsync(event, effects, decoded.value, caps, {
              selectedEvent: projected,
              admitStagedEvent: (temporary) => {
                admitContracts(options.contracts, temporary, state);
                budget!.check();
              },
              resolveAttachment: (part) => manager.restoreAttachment(part, event, projected),
              state,
              ...(originalRequest
                ? { elicitationRequest: originalRequest }
                : {}),
            }),
            deadline,
          );
          budget.check();
          admitContracts(options.contracts, staged.event, staged.state, decoded.value.result.effects ?? []);
          budget.check();
          decodeSettledState(decodeSettledEvent(staged.event), staged.state);
          event = staged.event;
          effects = staged.effects;
          state = staged.state;
          acceptedResponses.push(freezeContractValue(structuredClone(decoded.value)) as BoundaryResult<K>["acceptedResponses"][number]);
          shortCircuit = staged.shortCircuit;
        } catch (cause) {
          interrupted = signal.aborted;
          const syntheticDenial =
            !interrupted && s.failurePolicy === "fail-closed";
          const error: DeliveryFailure = {
            backendId: route.backend.id,
            subscriptionIndex: route.index,
            phase,
            code: interrupted
              ? cancellationCode(signal)
              : deadline?.aborted
                ? "DEADLINE_EXCEEDED"
                : phase === "preparation"
                  ? "PREPARATION_FAILED"
                  : "DELIVERY_FAILED",
            failurePolicy: s.failurePolicy as "fail-open" | "fail-closed",
            syntheticDenial,
          };
          diagnosticCauses.set(
            error,
            diagnosticCause(
              cause,
              signal.aborted ? signal : deadline,
              phase === "preparation",
              received,
            ),
          );
          errors.push(error);
          if (interrupted) break;
          if (syntheticDenial) {
            const denial: ComposedEffect = {
              type: "deny",
              reason: "Required policy backend unavailable.",
            };
            const settled = normalizeEffects([denial], state);
            effects = normalizeEffects([...effects, denial]).effects;
            state = settled.state;
            shortCircuit = settled.shortCircuit;
          }
        } finally {
          budget?.dispose();
        }
      }
      interrupted ||= signal.aborted;
      if (interrupted)
        effects = effects.filter(
          (e) =>
            e.type !== "allow" &&
            e.type !== "return" &&
            !(e.type === "flow" && e.operation === "continue"),
        );
      // Observation deliveries are owned by this call, but cannot change its decision.
      const observations = matching.filter(
        (r) =>
          advertised.modes.includes("observe") &&
          (r.subscription.mode === "observe" ||
            ((shortCircuit || interrupted) && !called.has(r))),
      );
      let observed: Promise<DeliveryFailure[]> = Promise.resolve([]);
      // Cancellation stops new work, including settlement notifications. Each
      // observer budget can shorten, but never extend, the operation signal.
      if (!signal.aborted && observations.length) {
        const snapshot = cloneInput(event);
        const jobs = observations.map((route) =>
          this.observe(route, snapshot, manager, signal, preparationFailures),
        );
        observed = Promise.all(jobs).then((results) =>
          results.filter(
            (result): result is DeliveryFailure => result !== undefined,
          ),
        );
        await observed;
      }
      interrupted ||= signal.aborted;
      if (type === "user.elicitation.result")
        this.forgetElicitation(event.parentEventId);
      if (
        type === "user.elicitation.request" &&
        (interrupted ||
          errors.length > 0 ||
          (await observed).length > 0 ||
          effects.some((e) => e.type === "deny"))
      )
        this.forgetElicitation(event.id);
      if (type === "session.end")
        this.retireSessionElicitations(event.session?.id);
      return {
        event: decodeSettledEvent<K>(event),
        content: manager.resultContent(event),
        effects: Object.freeze(effects.filter(effect => effect.type !== "modify" && effect.type !== "return")),
        acceptedResponses: Object.freeze(acceptedResponses),
        state: snapshotState(state),
        diagnostics: [...errors, ...(await observed)].map(deliveryDiagnostic),
        interrupted,
      } as BoundaryResult<K>;
    } catch (error) {
      if (type === "user.elicitation.request")
        this.forgetElicitation(requestId);
      await manager.close().catch(() => {});
      this.managers.delete(manager);
      if (error instanceof SettlementDecodeError)
        throw new SettlementDecodeError(error.message, Object.freeze([...acceptedResponses]),
          freezeContractValue(structuredClone(state)), { cause: error });
      throw error;
    } finally {
      await correlation?.release().catch(() => {});
    }
  }

  private async observe(
    route: Route,
    event: any,
    manager: ContentManager,
    parentSignal: AbortSignal,
    preparationFailures: Map<Route, unknown>,
  ): Promise<DeliveryFailure | undefined> {
    const budget = deadlineAfter(
      this.options.observationTimeoutMs ?? 15000,
      parentSignal,
    );
    const signal = budget.signal;
    let preparing = true;
    try {
      const s = route.subscription;
      if (preparationFailures.has(route)) throw preparationFailures.get(route);
      const projected = await raceAbort(
        manager.prepare(
          projectNative(event, s.includeNative),
          s.content,
          s.upload,
          (url, init, upload) =>
            this.fetchAuthenticated(
              url,
              init,
              upload.auth,
              "upload",
              route.backend.id,
            ),
          signal,
          route,
        ),
        signal,
      );
      preparing = false;
      await route.transport.notify(
        {
          jsonrpc: "2.0",
          method: "hooks/observe",
          params: { protocolVersion: "draft", event: projected },
        },
        signal,
      );
    } catch (cause) {
      const error: DeliveryFailure = {
        backendId: route.backend.id,
        subscriptionIndex: route.index,
        phase: "observation",
        code: parentSignal.aborted
          ? cancellationCode(parentSignal)
          : signal.aborted
            ? "DEADLINE_EXCEEDED"
            : "DELIVERY_FAILED",
        syntheticDenial: false,
      };
      diagnosticCauses.set(
        error,
        diagnosticCause(cause, signal, preparing, false),
      );
      return error;
    } finally {
      budget.dispose();
    }
  }

  private rememberElicitation(
    event: any,
    size: number,
    exchange: ElicitationLifetime,
  ): void {
    if (exchange.retired || this.lifetime.signal.aborted || this.elicitations.has(event.id)) {
      return;
    }
    const limit = this.options.maxContentBytes ?? 64 * 1024 * 1024;
    if (size > limit) {
      throw new Error("Elicitation request exceeds retention budget");
    }
    if (
      this.elicitationBytes + size > limit ||
      this.elicitations.size >= 128
    ) {
      throw new Error("Active elicitation exchanges exceed retention budget");
    }
    // Pending exchanges retain only the selected inline request and correlation facts.
    const stored = {
      type: event.type,
      id: event.id,
      source: event.source,
      session: event.session ? { id: event.session.id } : undefined,
      elicitation: {
        mode: event.elicitation.mode,
        server: event.elicitation.server,
        request: { ...event.elicitation.request },
      },
    };
    this.elicitations.set(event.id, { event: stored, size });
    this.elicitationBytes += size;
  }
  private elicitationFor(event: any): {
    event: Event; release: () => Promise<void>;
  } | undefined {
    if (event.type !== "user.elicitation.result") return undefined;
    const entry = this.elicitations.get(event.parentEventId);
    if (!entry) return undefined;
    const copy = cloneInput(entry.event);
    return { event: copy, release: async () => {} };
  }
  /** End an abandoned host elicitation exchange without delivering a result. */
  discardElicitation(requestEventId: string): void {
    this.forgetElicitation(requestEventId);
  }

  private retireSessionElicitations(sessionId: string | undefined): void {
    for (const exchange of this.activeElicitations)
      if (exchange.sessionId === sessionId) exchange.retired = true;
    for (const [id, entry] of this.elicitations)
      if (entry.event.session?.id === sessionId) this.forgetElicitation(id);
  }

  private forgetElicitation(id: string): void {
    for (const exchange of this.activeElicitations)
      if (exchange.id === id) exchange.retired = true;
    const entry = this.elicitations.get(id);
    if (entry) {
      this.elicitationBytes -= entry.size;
    }
    this.elicitations.delete(id);
  }

  /** Cancel pending work and release SDK-owned resources; injected stores remain owned by the host. */
  close(): Promise<void> {
    if (!this.closed) {
      for (const exchange of this.activeElicitations) exchange.retired = true;
      this.lifetime.abort(new Error("Hooks closed"));
      this.unavailable.clear();
      this.syncPrepared();
      this.closed = (async () => {
        await this.initialized.catch(() => {});
        await this.admission?.catch(() => {});
        await Promise.allSettled(
          [...new Set(this.routes.map((r) => r.transport))].map((t) =>
            t.close(),
          ),
        );
        await Promise.allSettled([...this.managers].map((m) => m.close()));
        await Promise.allSettled([...this.pending]);
        this.authContexts.clear();
        this.elicitations.clear();
        this.elicitationBytes = 0;
      })();
    }
    return this.closed;
  }
  private boundary<K extends EventType>(
    type: K,
    input: EventInput<K>,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<K>> {
    // Conversion is schema-bounded and has no I/O. Restore pending owners only
    // inside the runtime, before selection replaces them with confirmed refs.
    try {
      const host = mapParts({ ...input, type }, (part) =>
        part?.kind === "attachment" && part.body instanceof Attachment
          ? { ...part, body: ownedAttachment(part.body) } : part);
      const projection = _projectHostInput(type, host as any);
      if (type === "tool.before" && options?.contracts?.arguments) {
        // Projection owns this container; encode caller-defined values before JSON delivery.
        const projected = projection.event as any;
        projected.tool = { ...projected.tool, input: encodeContract(options.contracts.arguments, (input as any).input) };
      }
      bindContentSources(type, projection.event, projection.bindings as any);
      return this.dispatch(type, projection.event as unknown as BoundaryInput<K>, options);
    } catch (error) {
      const owners = new Set(localParts({ ...input, type }).map(({ part }) => part?.body).filter(body => body instanceof Attachment));
      // Admit cleanup ownership through the same synchronous nominal claim as
      // dispatch. Conflicting/read owners stay with their existing owner; own()
      // still admits every fresh source before reporting a conflict.
      const cleanup = new ContentManager();
      try { cleanup.own([...owners]); } catch { /* Never close an owner whose claim failed. */ }
      return cleanup.close().then(() => { throw error; });
    }
  }

  toolBefore<C extends BoundaryContracts>(
    input: ToolBeforeInput<C extends { arguments: Codec<infer A> } ? A : unknown>,
    options: Omit<BoundaryOptions, "contracts"> & { contracts: C },
  ): Promise<ToolBeforeResult<
    C extends { arguments: Codec<infer A> } ? A : unknown,
    C extends { result: Codec<infer R> } ? R : unknown,
    C extends { provenance: Codec<infer P> } ? P : unknown
  >>;
  toolBefore(input: ToolBeforeInput, options?: BoundaryOptions): Promise<ToolBeforeResult>;
  toolBefore(
    input: ToolBeforeInput,
    options?: BoundaryOptions,
  ): Promise<ToolBeforeResult> {
    return this.boundary("tool.before", input, options).then(settled => {
      try {
        const contracts = options?.contracts;
        const accepted = contracts?.arguments
          ? decodeContract(contracts.arguments, settled.event.tool.input) : settled.event.tool.input;
        const candidate = settled.state.candidate;
        const typedCandidate = candidate === null ? null : freezeContractValue({
          ...candidate,
          value: contracts?.result ? decodeContract(contracts.result, candidate.value) : candidate.value,
          ...(candidate.provenance !== undefined ? { provenance: contracts?.provenance
            ? decodeContract(contracts.provenance, candidate.provenance) : candidate.provenance } : {}),
        });
        return { ...settled,
          event: { ...settled.event, tool: { ...settled.event.tool, input: accepted } },
          state: Object.freeze({ ...settled.state, candidate: typedCandidate }),
        } as ToolBeforeResult;
      } catch (cause) {
        throw new SettlementDecodeError("Caller settlement decoding failed", settled.acceptedResponses, settled.state, { cause });
      }
    });
  }
  toolAfter(
    input: EventInput<"tool.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.after">> {
    return this.boundary("tool.after", input, options);
  }
  sessionStart(
    input: EventInput<"session.start">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"session.start">> {
    return this.boundary("session.start", input, options);
  }
  sessionEnd(
    input: EventInput<"session.end">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"session.end">> {
    return this.boundary("session.end", input, options);
  }
  configChangeBefore(
    input: EventInput<"config.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"config.change.before">> {
    return this.boundary("config.change.before", input, options);
  }
  configChangeAfter(
    input: EventInput<"config.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"config.change.after">> {
    return this.boundary("config.change.after", input, options);
  }
  turnStart(
    input: EventInput<"turn.start">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.start">> {
    return this.boundary("turn.start", input, options);
  }
  turnFinishBefore(
    input: EventInput<"turn.finish.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.finish.before">> {
    return this.boundary("turn.finish.before", input, options);
  }
  turnEnd(
    input: EventInput<"turn.end">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.end">> {
    return this.boundary("turn.end", input, options);
  }
  turnProgress(
    input: EventInput<"turn.progress">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"turn.progress">> {
    return this.boundary("turn.progress", input, options);
  }
  modelRequestBefore(
    input: EventInput<"model.request.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.request.before">> {
    return this.boundary("model.request.before", input, options);
  }
  modelResponseAfter(
    input: EventInput<"model.response.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.response.after">> {
    return this.boundary("model.response.after", input, options);
  }
  modelError(
    input: EventInput<"model.error">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.error">> {
    return this.boundary("model.error", input, options);
  }
  modelSwitchBefore(
    input: EventInput<"model.switch.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.switch.before">> {
    return this.boundary("model.switch.before", input, options);
  }
  modelSwitchAfter(
    input: EventInput<"model.switch.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"model.switch.after">> {
    return this.boundary("model.switch.after", input, options);
  }
  toolPermissionRequest(
    input: EventInput<"tool.permission.request">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.permission.request">> {
    return this.boundary("tool.permission.request", input, options);
  }
  toolPermissionResolved(
    input: EventInput<"tool.permission.resolved">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.permission.resolved">> {
    return this.boundary("tool.permission.resolved", input, options);
  }
  toolProgress(
    input: EventInput<"tool.progress">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.progress">> {
    return this.boundary("tool.progress", input, options);
  }
  toolBatchAfter(
    input: EventInput<"tool.batch.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"tool.batch.after">> {
    return this.boundary("tool.batch.after", input, options);
  }
  contextCompactBefore(
    input: EventInput<"context.compact.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"context.compact.before">> {
    return this.boundary("context.compact.before", input, options);
  }
  contextCompactAfter(
    input: EventInput<"context.compact.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"context.compact.after">> {
    return this.boundary("context.compact.after", input, options);
  }
  taskChangeBefore(
    input: EventInput<"task.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"task.change.before">> {
    return this.boundary("task.change.before", input, options);
  }
  taskChangeAfter(
    input: EventInput<"task.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"task.change.after">> {
    return this.boundary("task.change.after", input, options);
  }
  userAttention(
    input: EventInput<"user.attention">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.attention">> {
    return this.boundary("user.attention", input, options);
  }
  userElicitationRequest(
    input: EventInput<"user.elicitation.request">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.elicitation.request">> {
    return this.boundary("user.elicitation.request", input, options);
  }
  userElicitationResult(
    input: EventInput<"user.elicitation.result">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.elicitation.result">> {
    return this.boundary("user.elicitation.result", input, options);
  }
  userMessageInbound(
    input: EventInput<"user.message.inbound">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.message.inbound">> {
    return this.boundary("user.message.inbound", input, options);
  }
  userMessageOutbound(
    input: EventInput<"user.message.outbound">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"user.message.outbound">> {
    return this.boundary("user.message.outbound", input, options);
  }
  workspaceChangeBefore(
    input: EventInput<"workspace.change.before">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"workspace.change.before">> {
    return this.boundary("workspace.change.before", input, options);
  }
  workspaceChangeAfter(
    input: EventInput<"workspace.change.after">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"workspace.change.after">> {
    return this.boundary("workspace.change.after", input, options);
  }
  fileChanged(
    input: EventInput<"file.changed">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"file.changed">> {
    return this.boundary("file.changed", input, options);
  }
  hookFailure(
    input: EventInput<"hook.failure">,
    options?: BoundaryOptions,
  ): Promise<BoundaryResult<"hook.failure">> {
    return this.boundary("hook.failure", input, options);
  }
}

function cloneInput(value: any): any {
  return mapParts(value, (part) => {
    if (part === null || typeof part !== "object") return part;
    const copy = { ...part };

    return copy;
  });
}

function projectNative(event: any, includeNative?: boolean): any {
  const copy = cloneInput(event);
  if (includeNative !== true) delete copy.native;
  return copy;
}
// Only known capability fields carry permission semantics. Extension fields at
// every level remain opaque; their values must not affect local narrowing.
const modifyOperations = { replace: true, merge: true };
const capabilitySemantics = {
  effects: true,
  elicitation: { form: {}, url: {} },
  flow: {
    operations: true,
    continuationCount: true,
    maxContinuations: true,
    remainingContinuations: true,
  },
  inject: { context: { append: true, deliverAt: true } },
  modify: Object.fromEntries(
    [
      "content",
      "input",
      "instructions",
      "output",
      "prompt",
      "request",
      "response",
      "summary",
      "workspace",
    ].map((target) => [target, modifyOperations]),
  ),
};
function isNarrower(
  next: any,
  previous: any,
  semantics: any = capabilitySemantics,
): boolean {
  if (semantics === true) {
    if (Array.isArray(next))
      return Array.isArray(previous) && next.every((v) => previous.includes(v));
    if (typeof next === "number" && typeof previous === "number")
      return next <= previous;
    return next === previous || next === false;
  }
  return Object.entries(next).every(
    ([key, value]) =>
      !Object.hasOwn(semantics, key) ||
      (key === "continuationCount"
        ? typeof value === "number" && value >= (previous?.[key] ?? 0)
        : (semantics[key] === true || previous?.[key] !== undefined) &&
          isNarrower(value, previous?.[key], semantics[key])),
  );
}
function combineSignals(first: AbortSignal, second?: AbortSignal): AbortSignal {
  return second ? AbortSignal.any([first, second]) : first;
}
function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    promise
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
    // The operation already exists: own its rejection even if cancellation
    // occurred synchronously while constructing it.
    if (signal.aborted) abort();
  });
}

function secureEndpoint(value: string): void {
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    url.username ||
    url.password ||
    url.hash ||
    !(url.protocol === "https:" || (url.protocol === "http:" && loopback))
  )
    throw new Error("Unsafe endpoint");
}

function deadlineAfter(ms: number, parent: AbortSignal) {
  const controller = new AbortController();
  const expires = Date.now() + ms;
  const timer = setTimeout(
    () =>
      controller.abort(
        new DOMException("Hook deadline exceeded", "TimeoutError"),
      ),
    ms,
  );
  const signal = combineSignals(parent, controller.signal);
  return {
    signal,
    dispose: () => clearTimeout(timer),
    check: () => {
      if (Date.now() >= expires)
        controller.abort(
          new DOMException("Hook deadline exceeded", "TimeoutError"),
        );
      signal.throwIfAborted();
    },
  };
}

function cancellationCode(
  signal: AbortSignal,
): "DEADLINE_EXCEEDED" | "INTERRUPTED" {
  return signal.reason?.name === "TimeoutError"
    ? "DEADLINE_EXCEEDED"
    : "INTERRUPTED";
}

// Causes remain separate from delivery stage and never retain raw endpoint data.
const diagnosticCauses = new WeakMap<
  DeliveryFailure,
  Pick<DeliveryDiagnostic, "code" | "auth">
>();
function deliveryDiagnostic(error: DeliveryFailure): DeliveryDiagnostic {
  const cause = diagnosticCauses.get(error);
  return { ...error, code: cause?.code ?? "transport", ...(cause?.auth ? { auth: cause.auth } : {}) };
}
/** The typed auth failure in a cause chain, re-validated so only safe fields survive. */
function authFailure(cause: unknown): DeliveryDiagnostic["auth"] {
  for (let current = cause, depth = 0; current && typeof current === "object" && depth < 4; depth++) {
    let name: unknown, next: unknown;
    try { ({ name, cause: next } = current as { name?: unknown; cause?: unknown }); } catch { return undefined; }
    if (name === "AuthError") {
      const error = classifyAuthError(current, "provider_failed");
      return Object.freeze({ code: error.code, recovery: error.recovery,
        ...(error.requiredScopes ? { requiredScopes: error.requiredScopes } : {}) });
    }
    current = next;
  }
  return undefined;
}
function diagnosticCause(
  cause: unknown,
  signal: AbortSignal | undefined,
  preparing: boolean,
  received: boolean,
): Pick<DeliveryDiagnostic, "code" | "auth"> {
  const code = classifyDiagnostic(cause, signal, preparing, received);
  const auth = code === "cancelled" || code === "deadline_exceeded" ? undefined : authFailure(cause);
  return auth ? { code, auth } : { code };
}
function classifyDiagnostic(
  cause: unknown,
  signal: AbortSignal | undefined,
  preparing: boolean,
  received: boolean,
): DeliveryDiagnostic["code"] {
  if (signal?.aborted)
    return signal.reason?.name === "TimeoutError"
      ? "deadline_exceeded"
      : "cancelled";
  if (cause instanceof Error && cause.name === "TimeoutError")
    return "deadline_exceeded";
  if (cause instanceof HookOperationalError) {
    if (cause.code === "JSON_RPC_ERROR") return "remote_rpc";
    if (
      [
        "MALFORMED_UTF8",
        "MALFORMED_JSON",
        "MALFORMED_JSON_RPC",
        "ID_MISMATCH",
        "INCOMPATIBLE_VERSION",
        "UNSUPPORTED_EVENT",
        "UNSUPPORTED_EFFECT",
        "MULTIPLE_EFFECTS",
      ].includes(cause.code)
    )
      return "protocol_rejection";
  }
  if (preparing) return "preparation";
  return received ? "protocol_rejection" : "transport";
}

/** Only schema-derived named slots may receive out-of-band sources. */
function bindContentSources(
  type: EventType,
  event: any,
  bindings: BoundaryOptions["contentSources"],
): void {
  const used = new Set<string>();
  for (const binding of bindings ?? []) {
    const source = binding.source;
    if (!(source instanceof Attachment))
      throw new TypeError("Expected an owned content source");
    const path = binding.path;
    const allowed = isPartPath(type, path);
    const key = JSON.stringify(path);
    if (!allowed || used.has(key))
      throw new TypeError("Invalid or duplicate content source slot");
    used.add(key);
    let parent = event;
    for (const part of path.slice(0, -1)) {
      parent = parent?.[part];
      if (!parent || typeof parent !== "object")
        throw new TypeError("Missing content source descriptor");
    }
    const last = path[path.length - 1]!;
    const descriptor = parent[last];
    if (!descriptor || typeof descriptor !== "object" || descriptor.kind !== "attachment")
      throw new TypeError("Only binary attachment descriptors accept owned sources");
    if (descriptor.body !== undefined)
      throw new TypeError("Content source conflicts with an existing body");
    descriptor.body = source;
    descriptor.selection = "body";
  }
}

function clampContinuations(remaining: number | bigint, maximum: number | bigint, count: number | bigint): number | bigint {
  if (typeof remaining === "bigint" || typeof maximum === "bigint" || typeof count === "bigint") {
    const budget = BigInt(maximum) - BigInt(count);
    const available = BigInt(remaining);
    return budget <= 0n ? 0n : available < budget ? available : budget;
  }
  return Math.max(0, Math.min(remaining, maximum - count));
}
