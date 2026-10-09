import {
  parseContentUploadReceipt,
  type ContentSelection,
  type ContentUpload,
} from "../draft/generated.js";

/** An owned native content stream, distinct from a receiver content reference.
 * Construction does not read, lock, or upload the stream. Passing this source to
 * an awaited SDK operation transfers cleanup responsibility to that operation;
 * callers must not consume or reuse the underlying stream afterward. Native
 * streams can prefetch independently; use highWaterMark: 0 to disable that.
 */
export class ContentSource {
  readonly #stream: ReadableStream<Uint8Array>;

  constructor(stream: ReadableStream<Uint8Array>) {
    if (!(stream instanceof ReadableStream))
      throw new Error("Content source requires a native ReadableStream");
    this.#stream = stream;
  }

  /** Native stream identity is preserved for snapshot sharing and cleanup. */
  get stream(): ReadableStream<Uint8Array> {
    return this.#stream;
  }
}

/** An invocation-owned attachment. Metadata remains on its content item.
 * A handle can occur in multiple slots in one invocation, but cannot be reused
 * across invocations. Use a new attachment for each invocation.
 */
export class Attachment extends ContentSource {
  private constructor(
    stream: ReadableStream<Uint8Array>,
    dispose: () => Promise<void>,
  ) {
    super(stream);
    ownedAttachments.set(stream, { dispose });
  }

  /** Snapshot mutable caller bytes immediately. */
  static bytes(bytes: Uint8Array): Attachment {
    let copy: Uint8Array | undefined = new Uint8Array(bytes);
    return Attachment.lazy(() => copy!, () => { copy = undefined; });
  }

  /** Open at most once, only when selected bytes or result bytes are demanded.
   * dispose runs even if open is never called. It must release producer resources
   * promptly; cancellation does not wait for an uncooperative open callback.
   */
  static lazy(
    open: (signal: AbortSignal) => Uint8Array | Promise<Uint8Array>,
    dispose: () => void | Promise<void> = () => {},
  ): Attachment {
    const lifetime = new AbortController();
    let started = false;
    let disposed: Promise<void> | undefined;
    const cleanup = () => disposed ??= Promise.resolve().then(dispose);
    return new Attachment(new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (started) return;
        started = true;
        try {
          const bytes = await open(lifetime.signal);
          lifetime.signal.throwIfAborted();
          if (!(bytes instanceof Uint8Array))
            throw new TypeError("Attachment source must return Uint8Array");
          controller.enqueue(new Uint8Array(bytes));
          controller.close();
        } catch (error) {
          if (!lifetime.signal.aborted) controller.error(error);
        } finally {
          await cleanup();
        }
      },
      cancel(reason) {
        lifetime.abort(reason);
        return cleanup();
      },
    }, { highWaterMark: 0 }), cleanup);
  }
}

// Stream identity survives typed projection and source binding.
const ownedAttachments = new WeakMap<
  ReadableStream<Uint8Array>,
  { owner?: object; dispose: () => Promise<void> }
>();

/** Effective local content, independent of Hooks lifetime. Always close it.
 * Reads return independent byte copies; opaque remote references are not resolved.
 */
export class AttachmentContent {
  private readonly bodies = new Map<string, ReadableStream<Uint8Array>>();
  constructor(private readonly manager: ContentManager, event: unknown) {
    const seen = new WeakSet<object>();
    const visit = (value: any, path: string): void => {
      if (!value || typeof value !== "object" || seen.has(value)) return;
      const stream = sourceStream(value);
      if (stream) {
        this.bodies.set(path, stream);
        return;
      }
      seen.add(value);
      const body = sourceStream(value.body);
      if (typeof value.id === "string" && body) {
        if (this.bodies.has(value.id) && this.bodies.get(value.id) !== body)
          throw new Error("Ambiguous content item id");
        this.bodies.set(value.id, body);
      }
      for (const [key, child] of Object.entries(value)) {
        // Content item ids are the ergonomic key; reference-only slots use JSON pointers.
        if (key === "body" && body && typeof value.id === "string") continue;
        visit(child, path + "/" + key.replaceAll("~", "~0").replaceAll("/", "~1"));
      }
    };
    visit(event, "");
  }
  get ids(): readonly string[] {
    return [...this.bodies.keys()];
  }
  async read(id: string, signal?: AbortSignal): Promise<Uint8Array> {
    const body = this.bodies.get(id);
    if (!body) throw new Error("Unknown local content item id");
    return this.manager.readBody(body, signal);
  }
  close(): Promise<void> {
    this.bodies.clear();
    return this.manager.close();
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

type Snapshot = { bytes: Uint8Array; size: number; sha256: string };

/** One manager per producer/session. Selection is NOT authorization: callers must
 * authorize/project opaque native/input/output data before prepare. References
 * are deliberately never cached: each prepare uploads in its receiver's scope.
 */
export class ContentManager {
  private hasAttachments = false;
  private readonly ownership = {};

  /** @internal Transfer effective content ownership to the returned accessor. */
  resultContent(event: unknown): AttachmentContent | undefined {
    return this.hasAttachments ? new AttachmentContent(this, event) : undefined;
  }

  private snapshots = new WeakMap<
    ReadableStream<Uint8Array>,
    Promise<Snapshot>
  >();
  private readers = new Set<ReadableStreamDefaultReader<Uint8Array>>();
  private seenStreams = new Set<ReadableStream<Uint8Array>>();
  private lifetime = new AbortController();
  private retainedBytes = 0;
  private closePromise: Promise<void> | undefined;
  private readonly limit: number;
  private readonly allowLoopback: boolean;

  constructor(options: ContentManagerOptions = {}) {
    this.limit = options.maxSnapshotBytes ?? 64 * 1024 * 1024;
    if (!Number.isSafeInteger(this.limit) || this.limit < 0)
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
        if (ownedAttachments.has(stream)) {
          const attachment = ownedAttachments.get(stream)!;
          if (attachment.owner && attachment.owner !== this.ownership) {
            conflict = true;
            return;
          }
          attachment.owner = this.ownership;
          this.hasAttachments = true;
        }
        this.seenStreams.add(stream);
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
          if (value.size !== undefined && value.size !== snapshot.size)
            throw new Error("Content size mismatch");
          if (value.sha256 !== undefined && value.sha256 !== snapshot.sha256)
            throw new Error("Content SHA-256 mismatch");
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

  /** Copy an already selected snapshot without reading unselected sources. */
  async copySnapshot(
    body: ReadableStream<Uint8Array>,
  ): Promise<Uint8Array | undefined> {
    const snapshot = this.snapshots.get(body);
    if (!snapshot) return undefined;
    try {
      return (await snapshot).bytes.slice();
    } catch {
      // Failed reads have no reusable result payload; delivery reports the error.
      return undefined;
    }
  }

  /** Initiates cancellation and releases snapshots; repeated calls return the
   * same promise. Never waits for producer-controlled cancellation promises.
   */
  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closePromise = Promise.resolve();
    this.lifetime.abort(new Error("Content manager closed"));
    const readers = [...this.readers];
    this.snapshots = new WeakMap();
    const disposals = [...this.seenStreams].map(
      (stream) => ownedAttachments.get(stream)?.dispose,
    );
    const unread = [...this.seenStreams].filter((stream) => !stream.locked);
    this.seenStreams.clear();
    this.readers.clear();
    for (const reader of readers) void reader.cancel().catch(() => undefined);
    for (const stream of unread) void stream.cancel().catch(() => undefined);
    this.retainedBytes = 0;
    this.closePromise = Promise.all(
      disposals.map((dispose) => dispose?.()),
    ).then(() => {});
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

  private snapshot(
    stream: ReadableStream<Uint8Array>,
    signal: AbortSignal,
  ): Promise<Snapshot> {
    const existing = this.snapshots.get(stream);
    if (existing) return existing;
    const pending = this.readSnapshot(stream, signal);
    this.snapshots.set(stream, pending);
    return pending;
  }

  private async readSnapshot(
    stream: ReadableStream<Uint8Array>,
    signal: AbortSignal,
  ): Promise<Snapshot> {
    signal.throwIfAborted();
    const reader = stream.getReader();
    this.readers.add(reader);
    const chunks: Uint8Array[] = [];
    let size = 0;
    const cancel = () => {
      void reader.cancel(signal.reason).catch(() => undefined);
    };
    signal.addEventListener("abort", cancel, { once: true });
    try {
      for (;;) {
        const next = await abortable(reader.read(), signal);
        signal.throwIfAborted();
        if (next.done) break;
        if (!(next.value instanceof Uint8Array))
          throw new Error("Content stream must yield Uint8Array chunks");
        if (this.retainedBytes + next.value.byteLength > this.limit)
          throw new Error("Content snapshot memory limit exceeded");
        if (next.value.byteLength === 0) continue;
        chunks.push(next.value.slice());
        size += next.value.byteLength;
        this.retainedBytes += next.value.byteLength;
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      chunks.length = 0;
      const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", bytes),
      );
      signal.throwIfAborted();
      return {
        bytes,
        size,
        sha256: Array.from(digest, (byte) =>
          byte.toString(16).padStart(2, "0"),
        ).join(""),
      };
    } catch (error) {
      if (!this.lifetime.signal.aborted) this.retainedBytes -= size;
      void reader.cancel(error).catch(() => undefined);
      throw error;
    } finally {
      signal.removeEventListener("abort", cancel);
      this.readers.delete(reader);
      reader.releaseLock();
    }
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
