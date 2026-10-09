import {
  parseContentUploadReceipt,
  type ContentSelection,
  type ContentUpload,
} from "../draft/generated.js";

/** Compatibility adapter for a native lazy stream. The stream is consumed by
 * its attachment owner, not staged in an invocation store. */
export class ContentSource {
  readonly #stream: ReadableStream<Uint8Array>;
  constructor(stream: ReadableStream<Uint8Array>) {
    if (!(stream instanceof ReadableStream))
      throw new Error("Content source requires a native ReadableStream");
    this.#stream = stream;
  }
  get stream(): ReadableStream<Uint8Array> { return this.#stream; }
}

type ContentMetadata = { size?: number | undefined; sha256?: string | undefined };
type Snapshot = { bytes: Uint8Array; size: number; sha256: string };
type Budget = { used: number; limit: number };
type Loader = (signal: AbortSignal, reserve: (bytes: number) => void) => Promise<Uint8Array>;
// This is only an identity index for legacy native streams, never a byte store.
const streamOwners = new WeakMap<ReadableStream<Uint8Array>, Attachment>();
const retainedOwners = new WeakSet<Attachment>();
let ownerAccess: {
  claim(owner: Attachment, invocation: object, budget: Budget): void;
  snapshot(owner: Attachment, signal?: AbortSignal): Promise<Snapshot>;
  peek(owner: Attachment): Promise<Snapshot> | undefined;
  retain(owner: Attachment): () => Promise<void>;
  adapt(stream: ReadableStream<Uint8Array>): Attachment;
};

/** Sole backing owner for immutable bytes or an unread lazy source. Metadata
 * stays on content items. A handle may be shared within, but not across, calls. */
export class Attachment extends ContentSource {
  #load: Loader | undefined;
  #snapshot: Promise<Snapshot> | undefined;
  #lifetime = new AbortController();
  #invocation: object | undefined;
  #budget: Budget = { used: 0, limit: 64 * 1024 * 1024 };
  #reserved = 0;
  #dispose: () => void | Promise<void>;
  #disposal: Promise<void> | undefined;
  #closed: Promise<void> | undefined;
  #primaryRelease: Promise<void> | undefined;
  #leases = 1;

  private constructor(load: Loader, dispose: () => void | Promise<void>, retained = true) {
    let owner: Attachment;
    super(new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          controller.enqueue(await owner.read());
          controller.close();
        } catch (error) { controller.error(error); }
      },
      cancel() { return owner.close(); },
    }, { highWaterMark: 0 }));
    owner = this;
    this.#load = load;
    this.#dispose = dispose;
    streamOwners.set(this.stream, this);
    if (retained) retainedOwners.add(this);
  }

  static {
    ownerAccess = {
      claim(owner, invocation, budget) {
        if (owner.#invocation && owner.#invocation !== invocation)
          throw new Error("Attachment already belongs to another invocation");
        if (owner.#closed) throw new Error("Attachment closed");
        if (!owner.#invocation) {
          if (owner.#snapshot !== undefined)
            throw new Error("Read attachments cannot be transferred to an invocation");
          owner.#invocation = invocation;
          owner.#budget = budget;
        }
      },
      snapshot: (owner, signal) => owner.#materialize(signal),
      peek: (owner) => owner.#snapshot,
      adapt: (stream) => Attachment.#fromStream(stream),
      retain(owner) {
        owner.#lifetime.signal.throwIfAborted();
        owner.#leases++;
        let released: Promise<void> | undefined;
        return () => released ??= owner.#release();
      },
    };
  }

  /** One defensive input copy, retained directly by this owner. */
  static bytes(bytes: Uint8Array): Attachment {
    let initial: Uint8Array | undefined = new Uint8Array(bytes);
    return new Attachment(async (_signal, reserve) => {
      const bytes = initial!;
      reserve(bytes.byteLength);
      initial = undefined;
      return bytes;
    }, () => { initial = undefined; });
  }

  /** Evaluated once, on demand. The returned mutable buffer is copied once. */
  static lazy(
    open: (signal: AbortSignal) => Uint8Array | Promise<Uint8Array>,
    dispose: () => void | Promise<void> = () => {},
  ): Attachment {
    return new Attachment(async (signal, reserve) => {
      const bytes = await open(signal);
      signal.throwIfAborted();
      if (!(bytes instanceof Uint8Array))
        throw new TypeError("Attachment source must return Uint8Array");
      reserve(bytes.byteLength);
      return new Uint8Array(bytes);
    }, dispose);
  }

  /** Adapt a native source without a second snapshot cache. */
  static fromStream(stream: ReadableStream<Uint8Array>): Attachment {
    if (!(stream instanceof ReadableStream))
      throw new TypeError("Attachment source requires a native ReadableStream");
    const owner = Attachment.#fromStream(stream);
    retainedOwners.add(owner);
    return owner;
  }

  static #fromStream(stream: ReadableStream<Uint8Array>): Attachment {
    const existing = streamOwners.get(stream);
    if (existing) return existing;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const owner = new Attachment(async (signal, reserve) => {
      reader = stream.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      const cancel = () => { void reader?.cancel(signal.reason).catch(() => {}); };
      signal.addEventListener("abort", cancel, { once: true });
      try {
        for (;;) {
          const next = await abortable(reader.read(), signal);
          signal.throwIfAborted();
          if (next.done) break;
          if (!(next.value instanceof Uint8Array))
            throw new Error("Content stream must yield Uint8Array chunks");
          reserve(next.value.byteLength);
          chunks.push(new Uint8Array(next.value));
          size += next.value.byteLength;
        }
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        return bytes;
      } finally {
        signal.removeEventListener("abort", cancel);
        reader.releaseLock();
        reader = undefined;
      }
    }, () => {
      // Legacy native cancellation must not block shutdown on producer promises.
      if (reader) void reader.cancel().catch(() => {});
      else if (!stream.locked) void stream.cancel().catch(() => {});
    }, false);
    streamOwners.set(stream, owner);
    return owner;
  }

  #cleanup(): Promise<void> {
    if (!this.#disposal) {
      const dispose = this.#dispose;
      this.#dispose = () => {};
      this.#disposal = Promise.resolve().then(dispose);
    }
    return this.#disposal;
  }

  #materialize(signal?: AbortSignal): Promise<Snapshot> {
    this.#lifetime.signal.throwIfAborted();
    signal?.throwIfAborted();
    if (!this.#snapshot) {
      const load = this.#load!;
      this.#load = undefined;
      const abort = () => this.#lifetime.abort(signal?.reason);
      signal?.addEventListener("abort", abort, { once: true });
      this.#snapshot = (async () => {
        try {
          const bytes = await abortable(load(this.#lifetime.signal, (size) => {
            this.#lifetime.signal.throwIfAborted();
            if (this.#budget.used + size > this.#budget.limit)
              throw new Error("Content snapshot memory limit exceeded");
            this.#budget.used += size;
            this.#reserved += size;
          }), this.#lifetime.signal);
          this.#lifetime.signal.throwIfAborted();
          // All loaders allocate ordinary ArrayBuffers before returning bytes.
          const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>));
          this.#lifetime.signal.throwIfAborted();
          return { bytes, size: bytes.length,
            sha256: Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("") };
        } catch (error) {
          this.#budget.used -= this.#reserved;
          this.#reserved = 0;
          throw error;
        } finally {
          signal?.removeEventListener("abort", abort);
          await this.#cleanup();
        }
      })();
    }
    return signal ? abortable(this.#snapshot, signal) : this.#snapshot;
  }

  /** Defensive caller copy; uploads use the same private materialization. */
  async read(signal?: AbortSignal, metadata: ContentMetadata = {}): Promise<Uint8Array> {
    const snapshot = await this.#materialize(signal);
    validateSnapshotMetadata(snapshot, metadata);
    return snapshot.bytes.slice();
  }

  close(): Promise<void> {
    return this.#primaryRelease ??= this.#release();
  }

  #release(): Promise<void> {
    if (--this.#leases !== 0) return Promise.resolve();
    if (this.#closed) return this.#closed;
    this.#lifetime.abort(new Error("Attachment closed"));
    this.#load = undefined;
    this.#snapshot = undefined;
    this.#budget.used -= this.#reserved;
    this.#reserved = 0;
    return this.#closed = this.#cleanup();
  }
}

/** Effective slot index. Owners, not an invocation manager, outlive Hooks. */
export class AttachmentContent {
  private readonly bodies = new Map<string, ContentMetadata & { owner: Attachment }>();
  private readonly owners = new Set<Attachment>();
  private closed: Promise<void> | undefined;
  constructor(event: unknown) {
    const seen = new WeakSet<object>();
    const visit = (value: any, path: string): void => {
      if (!value || typeof value !== "object" || seen.has(value)) return;
      const stream = sourceStream(value);
      if (stream) {
        const owner = ownerAccess.adapt(stream);
        this.bodies.set(path, { owner });
        this.owners.add(owner);
        return;
      }
      seen.add(value);
      const body = sourceStream(value.body);
      if (typeof value.id === "string" && body) {
        const owner = ownerAccess.adapt(body);
        const previous = this.bodies.get(value.id);
        if (previous && (previous.owner !== owner || previous.size !== value.size || previous.sha256 !== value.sha256))
          throw new Error("Ambiguous content item id");
        this.bodies.set(value.id, { owner, size: value.size, sha256: value.sha256 });
        this.owners.add(owner);
      }
      for (const [key, child] of Object.entries(value)) {
        if (key === "body" && body && typeof value.id === "string") continue;
        visit(child, path + "/" + key.replaceAll("~", "~0").replaceAll("/", "~1"));
      }
    };
    visit(event, "");
  }
  get ids(): readonly string[] { return [...this.bodies.keys()]; }
  /** @internal Transfer cleanup responsibility without copying backing bytes. */
  detachFrom(pending: Set<Attachment>): void {
    for (const owner of this.owners) pending.delete(owner);
  }
  async read(id: string, signal?: AbortSignal): Promise<Uint8Array> {
    const body = this.bodies.get(id);
    if (!body) throw new Error("Unknown local content item id");
    return body.owner.read(signal, body);
  }
  close(): Promise<void> {
    if (this.closed) return this.closed;
    this.bodies.clear();
    this.closed = Promise.all([...this.owners].map(owner => owner.close())).then(() => {});
    this.owners.clear();
    return this.closed;
  }
}

function sourceStream(value: unknown): ReadableStream<Uint8Array> | undefined {
  if (value instanceof ContentSource) return value.stream;
  return value instanceof ReadableStream ? value : undefined;
}

/** Producer content is metadata with an owned source or raw stream in `body`. */
export interface StreamContentItem {
  id: string;
  kind: string;
  mediaType: string;
  body: ContentSource | ReadableStream<Uint8Array>;
  category?: string;
  size?: number;
  sha256?: string;
  [key: string]: unknown;
}

/** Authenticate this upload independently, including discovery when auth is absent.
 * Implementations must honor init.signal and init.redirect; never reuse event credentials.
 */
export type ContentUploadRequest = (
  endpoint: string,
  init: RequestInit,
  upload: ContentUpload,
) => Promise<Response>;

export interface ContentManagerOptions {
  /** Aggregate retained byte limit, not a truncation threshold. Default: 64 MiB.
   * Snapshots are kept until close. Chunk assembly, hashing, and each concurrent
   * request also use bounded copies. Streams exceeding it fail explicitly.
   */
  maxSnapshotBytes?: number;
  allowLoopback?: boolean;
}

function validateSnapshotMetadata(snapshot: Snapshot, metadata: ContentMetadata): void {
  if (metadata.size !== undefined && metadata.size !== snapshot.size)
    throw new Error("Content size mismatch");
  if (metadata.sha256 !== undefined && metadata.sha256 !== snapshot.sha256)
    throw new Error("Content SHA-256 mismatch");
}

/** Per-invocation delivery and cleanup coordinator, not a content store.
 * Byte materialization lives only in Attachment. This class retains owner
 * identities and non-owning aggregate budget counters, never byte buffers.
 * Selection is not authorization; project opaque host data before prepare.
 */
export class ContentManager {
  private hasAttachments = false;
  private readonly ownership = {};

  /** @internal Build a slot index retaining the existing owners. */
  resultContent(event: unknown): AttachmentContent | undefined {
    return this.hasAttachments ? new AttachmentContent(event) : undefined;
  }

  private readonly attachments = new Set<Attachment>();
  private lifetime = new AbortController();
  private closePromise: Promise<void> | undefined;
  private readonly budget: Budget;
  private readonly allowLoopback: boolean;

  /** @internal Detach returned owners; dispose everything else in close(). */
  transfer(content: AttachmentContent): void { content.detachFrom(this.attachments); }

  constructor(options: ContentManagerOptions = {}) {
    const limit = options.maxSnapshotBytes ?? 64 * 1024 * 1024;
    this.budget = { used: 0, limit };
    if (!Number.isSafeInteger(limit) || limit < 0)
      throw new Error("Invalid snapshot byte limit");
    this.allowLoopback = options.allowLoopback ?? false;
  }

  /** Take cleanup ownership without selecting or reading any body. Call before
   * routing/projection so unmatched and unauthorized sources are also closed.
   * Close the manager in the operation's finally block, including on failure.
   */
  own(event: unknown): void {
    this.lifetime.signal.throwIfAborted();
    const visited = new WeakSet<object>();
    let conflict = false;
    const visit = (value: unknown): void => {
      if (value === null || typeof value !== "object" || visited.has(value))
        return;
      visited.add(value);
      const stream = sourceStream(value);
      if (stream) {
        const existing = streamOwners.get(stream);
        const owner = ownerAccess.adapt(stream);
        try { ownerAccess.claim(owner, this.ownership, this.budget); }
        catch { conflict = true; return; }
        // Explicit Attachment sources opt into retained result ownership.
        if (existing && retainedOwners.has(existing)) this.hasAttachments = true;
        this.attachments.add(owner);
        return;
      }
      for (const child of Object.values(value)) visit(child);
    };
    visit(event);
    if (conflict) throw new Error("Attachment already belongs to another invocation");
  }

  /** Reads local producer bytes for composition, never remote references.
   * Reuses the same bounded snapshot as prepare; returns an independent copy.
   * Aborting the initial read cancels the stream and leaves that snapshot failed.
   */
  async readBody(
    body: ContentSource | ReadableStream<Uint8Array>,
    signal?: AbortSignal,
    metadata: ContentMetadata = {},
  ): Promise<Uint8Array> {
    this.lifetime.signal.throwIfAborted();
    this.own(body);
    signal?.throwIfAborted();
    const stream = sourceStream(body);
    if (!stream)
      throw new Error(
        "Content body must be a ContentSource or raw ReadableStream",
      );
    const controller = new AbortController();
    const abort = () =>
      controller.abort(signal?.reason ?? this.lifetime.signal.reason);
    signal?.addEventListener("abort", abort, { once: true });
    this.lifetime.signal.addEventListener("abort", abort, { once: true });
    if (signal?.aborted || this.lifetime.signal.aborted) abort();
    try {
      const snapshot = await abortable(
        this.snapshot(stream, controller.signal),
        controller.signal,
      );
      controller.signal.throwIfAborted();
      validateSnapshotMetadata(snapshot, metadata);
      return snapshot.bytes.slice();
    } finally {
      signal?.removeEventListener("abort", abort);
      this.lifetime.signal.removeEventListener("abort", abort);
    }
  }

  /** Returns a fresh wire tree; never mutates the producer event or reads an
   * omitted/metadata stream. All selected uploads finish before this resolves.
   */
  async prepare(
    event: any,
    selection: ContentSelection,
    upload: ContentUpload | undefined,
    send: ContentUploadRequest,
    signal?: AbortSignal,
  ): Promise<any> {
    this.lifetime.signal.throwIfAborted();
    this.own(event);
    signal?.throwIfAborted();
    const omitted = Symbol("omitted file content");
    const visit = async (
      value: any,
      path: Array<string | number> = [],
    ): Promise<any> => {
      if (event?.type === "file.changed" && isFileReferencePath(path)) {
        // Reuse normalized preparation internally; only the confirmed body is
        // emitted in this bare-reference slot. Private identity never goes out.
        const prepared = await visit(
          {
            id: "local-file-content",
            kind: "file",
            category: "files",
            mediaType: "application/octet-stream",
            body: value,
          },
          ["instructions"],
        );
        return prepared.body ?? omitted;
      }
      if (value === null || typeof value !== "object") return value;
      if (Array.isArray(value))
        return Promise.all(
          value.map((child, index) => visit(child, [...path, index])),
        );
      if (sourceStream(value)) return value;
      if (
        isContentPath(path) &&
        typeof value.id === "string" &&
        typeof value.kind === "string" &&
        typeof value.mediaType === "string"
      ) {
        const stream = sourceStream(value.body);
        const category =
          value.kind === "reasoning"
            ? "reasoning"
            : (value.category ?? mediaCategory(value.mediaType));
        const mode = Object.hasOwn(selection, category)
          ? selection[category]
          : selection.default;
        if (mode !== "body" && mode !== "metadata" && mode !== "omit")
          throw new Error("Unsupported content selection");
        const result: Record<string, unknown> = {};
        for (const [key, child] of Object.entries(value)) {
          if (key !== "body" && key !== "gap" && key !== "selection")
            result[key] = await visit(child, [...path, key]);
        }
        result.selection = mode;
        if (mode !== "body") return result;
        if (value.gap !== undefined && value.body === undefined) {
          result.gap = await visit(value.gap, [...path, "gap"]);
          return result;
        }
        if (!stream)
          throw new Error(
            "Body selection requires a ContentSource or raw ReadableStream, not a receiver reference",
          );
        if (!upload)
          throw new Error("Body selection requires upload configuration");
        this.validateUpload(upload);
        const controller = new AbortController();
        const abort = () =>
          controller.abort(signal?.reason ?? this.lifetime.signal.reason);
        signal?.addEventListener("abort", abort, { once: true });
        this.lifetime.signal.addEventListener("abort", abort, { once: true });
        if (signal?.aborted || this.lifetime.signal.aborted) abort();
        const timeout = setTimeout(
          () =>
            controller.abort(
              new DOMException("Content upload timed out", "TimeoutError"),
            ),
          upload.timeoutMs,
        );
        try {
          const snapshot = await abortable(
            this.snapshot(stream, controller.signal),
            controller.signal,
          );
          validateSnapshotMetadata(snapshot, value);
          if (snapshot.size > upload.maxBytes)
            throw new Error("Content exceeds upload maxBytes");
          const response = await abortable(
            send(
              upload.endpoint,
              {
                method: "POST",
                redirect: "error",
                signal: controller.signal,
                headers: {
                  "content-type": "application/octet-stream",
                  "content-length": String(snapshot.size),
                  "ahp-content-sha256": snapshot.sha256,
                },
                // Never expose the reusable private snapshot to an injected callback.
                body: snapshot.bytes.slice(),
              },
              upload,
            ).then((response) => {
              if (controller.signal.aborted) {
                void response.body?.cancel().catch(() => undefined);
                controller.signal.throwIfAborted();
              }
              return response;
            }),
            controller.signal,
          );
          const parsed = parseContentUploadReceipt(
            await readConfirmation(response, controller.signal),
          );
          if (
            !parsed.ok ||
            parsed.value.size !== snapshot.size ||
            parsed.value.sha256 !== snapshot.sha256
          ) {
            throw new Error("Invalid or mismatched upload reference");
          }
          delete result.size;
          delete result.sha256;
          result.body = { ref: parsed.value.ref };
          return result;
        } finally {
          clearTimeout(timeout);
          signal?.removeEventListener("abort", abort);
          this.lifetime.signal.removeEventListener("abort", abort);
        }
      }
      const result: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(value)) {
        const prepared = await visit(child, [...path, key]);
        if (prepared !== omitted) result[key] = prepared;
      }
      return result;
    };
    return visit(event);
  }

  /** @internal A protocol correlation lease shares the same owner, never bytes. */
  async retainBody(body: ReadableStream<Uint8Array>, signal: AbortSignal): Promise<{
    owner: Attachment; size: number; release: () => Promise<void>;
  }> {
    const owner = ownerAccess.adapt(body);
    const snapshot = await ownerAccess.snapshot(owner, signal);
    return { owner, size: snapshot.size, release: ownerAccess.retain(owner) };
  }

  /** @internal Project compatibility results, or preserve the actual owner. */
  async resultBody(body: ReadableStream<Uint8Array>, synthesized: boolean): Promise<Attachment | ReadableStream<Uint8Array> | undefined> {
    const owner = ownerAccess.adapt(body);
    if (this.hasAttachments) return owner;
    const pending = ownerAccess.peek(owner);
    if (!synthesized && !pending) return undefined;
    try {
      if (synthesized) await ownerAccess.snapshot(owner);
      else await pending;
    } catch { return undefined; }
    // Legacy callers receive a lazy view of this same owner, not a queued copy.
    const release = ownerAccess.retain(owner);
    return new ReadableStream<Uint8Array>({
      async pull(controller) {
        try { controller.enqueue(await owner.read()); controller.close(); }
        catch (error) { controller.error(error); }
        finally { await release(); }
      },
      cancel() { return release(); },
    }, { highWaterMark: 0 });
  }

  /** @internal Invocation-scoped borrow of an active protocol exchange. */
  lease(owner: Attachment): () => Promise<void> { return ownerAccess.retain(owner); }

  /** Cancel and dispose remaining owners. No backing bytes live here. */
  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.lifetime.abort(new Error("Content manager closed"));
    this.closePromise = Promise.all([...this.attachments].map(owner => owner.close())).then(() => {});
    this.attachments.clear();
    return this.closePromise;
  }

  private validateUpload(upload: ContentUpload): void {
    const url = new URL(upload.endpoint);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (
      /[\r\n]/.test(upload.endpoint) ||
      url.username ||
      url.password ||
      url.hash ||
      (url.protocol !== "https:" &&
        !(this.allowLoopback && loopback && url.protocol === "http:"))
    )
      throw new Error("Unsafe upload endpoint");
    if (
      !Number.isSafeInteger(upload.maxBytes) ||
      upload.maxBytes < 0 ||
      !Number.isSafeInteger(upload.timeoutMs) ||
      upload.timeoutMs < 1
    )
      throw new Error("Invalid upload budget");
  }

  private snapshot(stream: ReadableStream<Uint8Array>, signal: AbortSignal): Promise<Snapshot> {
    return ownerAccess.snapshot(ownerAccess.adapt(stream), signal);
  }
}

function isFileReferencePath(path: Array<string | number>): boolean {
  return (
    path.length === 3 &&
    path[0] === "changes" &&
    typeof path[1] === "number" &&
    (path[2] === "before" || path[2] === "after")
  );
}

// Match positions, not descriptor-looking objects in opaque operation data.
function isContentPath(path: Array<string | number>): boolean {
  if (path.length === 1)
    return ["instructions", "summary", "partialOutput", "delta"].includes(
      String(path[0]),
    );
  if (path.length === 2) {
    return (
      (path[0] === "items" && typeof path[1] === "number") ||
      (path[0] === "elicitation" &&
        ["request", "result"].includes(String(path[1])))
    );
  }
  if (path.length !== 3) return false;
  return (
    (path[0] === "attention" &&
      ["title", "message"].includes(String(path[1])) &&
      typeof path[2] === "number") ||
    (path[0] === "message" &&
      ["text", "payload"].includes(String(path[1])) &&
      typeof path[2] === "number") ||
    (path[0] === "fileChanges" &&
      typeof path[1] === "number" &&
      ["before", "after"].includes(String(path[2])))
  );
  // Bare file.changed references are projected separately above.
}

async function readConfirmation(
  response: Response,
  signal: AbortSignal,
): Promise<unknown> {
  const reader = response.body?.getReader();
  try {
    signal.throwIfAborted();
    if (
      response.status !== 201 ||
      response.headers
        .get("content-type")
        ?.split(";")[0]
        ?.trim()
        .toLowerCase() !== "application/json"
    ) {
      throw new Error("Upload requires HTTP 201 application/json confirmation");
    }
    if (!reader) throw new Error("Missing upload confirmation body");
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const next = await abortable(reader.read(), signal);
      signal.throwIfAborted();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > 1024 * 1024)
        throw new Error("Upload confirmation exceeds 1 MiB limit");
      if (next.value.byteLength !== 0) chunks.push(next.value.slice());
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes),
    );
  } finally {
    if (reader) {
      // Cancellation settles outstanding reads without waiting for the source's
      // cancellation promise. Release the lock on every status/parse/abort path.
      void reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
  }
}

function mediaCategory(mediaType: string): string {
  const type = mediaType.toLowerCase().split(";")[0]!.trim();
  if (type.startsWith("text/") || type === "application/json") return "text";
  if (type.startsWith("image/")) return "images";
  if (type.startsWith("audio/")) return "audio";
  if (type.startsWith("video/")) return "video";
  return "files";
}

function abortable<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const abort = () =>
      reject(signal.reason ?? new Error("Content operation aborted"));
    signal.addEventListener("abort", abort, { once: true });
    pending
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
  });
}
