import { runtimeInteger, sameInteger } from "../runtime-integer.js";
import { isPartPath, localParts, mapParts } from "./content-paths.js";
import {
  parseContentUploadReceipt,
  type ContentSelection,
  type ContentUpload,
  type ContentUploadReceipt,
} from "../draft/raw.js";

type ContentMetadata = { size?: number | bigint | undefined; sha256?: string | undefined };
type Snapshot = { bytes: Uint8Array; size: number; sha256: string };
type Budget = { used: number; limit: number };
type Loader = (signal: AbortSignal, reserve: (bytes: number) => void) => Promise<Uint8Array>;
let ownerAccess: {
  claim(owner: Attachment, invocation: object, budget: Budget): void;
  snapshot(owner: Attachment, signal?: AbortSignal): Promise<Snapshot>;
  retain(owner: Attachment): () => Promise<void>;
};

/** Sole backing owner for immutable bytes or an unread lazy source. Metadata
 * stays on content items. A handle may be shared within, but not across, calls. */
export class Attachment {
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

  private constructor(load: Loader, dispose: () => void | Promise<void>) {
    this.#load = load;
    this.#dispose = dispose;
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

  /** Explicitly own a lazy native source. The source is consumed at most once. */
  static stream(stream: ReadableStream<Uint8Array>): Attachment {
    if (!(stream instanceof ReadableStream))
      throw new TypeError("Attachment source requires a native ReadableStream");
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
      // Request cancellation without awaiting producer cleanup, which may never settle.
      if (reader) void reader.cancel().catch(() => {});
      else if (!stream.locked) void stream.cancel().catch(() => {});
    });
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
    for (const { part: value, path } of localParts(event)) {
      const owner = attachmentOwner(value?.body);
      if (!owner) continue;
      const id = typeof value.id === "string" ? value.id : "/" + path.join("/");
      const previous = this.bodies.get(id);
      if (previous && (previous.owner !== owner || previous.size !== value.size || previous.sha256 !== value.sha256))
        throw new Error("Ambiguous content item id");
      this.bodies.set(id, { owner, size: value.size, sha256: value.sha256 });
      this.owners.add(owner);
    }
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

function attachmentOwner(value: unknown): Attachment | undefined {
  return value instanceof Attachment ? value : undefined;
}

/** Authenticate this upload independently, including discovery when auth is absent.
 * Implementations must honor init.signal and init.redirect; never reuse event credentials.
 */
export type ContentUploadRequest = (
  endpoint: string,
  init: RequestInit,
  upload: ContentUpload,
) => Promise<Response>;

/** @internal FIFO transfer slots shared by all calls on one Hooks instance.
 * Holds no content, owners, receipts, or invocation state. Aborted queued waiters
 * remove themselves; each active transfer releases its slot in finally.
 */
export class UploadLimiter {
  private activeUploads = 0;
  private readonly uploadQueue: { start: () => void }[] = [];

  constructor(private readonly maxConcurrentUploads = 8) {
    if (!Number.isSafeInteger(maxConcurrentUploads) || maxConcurrentUploads < 1)
      throw new Error("Invalid concurrent upload limit");
  }

  acquire(signal: AbortSignal): Promise<() => void> {
    signal.throwIfAborted();
    return new Promise((resolve, reject) => {
      const entry = { start: () => {
        signal.removeEventListener("abort", abort);
        this.activeUploads++;
        let released = false;
        resolve(() => {
          if (released) return;
          released = true;
          this.activeUploads--;
          this.uploadQueue.shift()?.start();
        });
      } };
      const abort = () => {
        const index = this.uploadQueue.indexOf(entry);
        if (index >= 0) this.uploadQueue.splice(index, 1);
        reject(signal.reason);
      };
      signal.addEventListener("abort", abort, { once: true });
      if (this.activeUploads < this.maxConcurrentUploads) entry.start();
      else this.uploadQueue.push(entry);
    });
  }

}

export interface ContentManagerOptions {
  /** Aggregate retained byte limit, not a truncation threshold. Default: 64 MiB.
   * Snapshots are kept until close. Chunk assembly, hashing, and each concurrent
   * request also use bounded copies. Streams exceeding it fail explicitly.
   */
  maxSnapshotBytes?: number;
  /** Standalone manager transfer limit. Default: 8. */
  maxConcurrentUploads?: number;
  allowLoopback?: boolean;
}

// Factory-only identity channel: no internal option leaks into public declarations.
const sharedUploadLimiters = new WeakMap<ContentManagerOptions, UploadLimiter>();

/** @internal Share transfer slots, never owners or content, across Hooks calls. */
export function createSharedContentManager(
  options: ContentManagerOptions,
  limiter: UploadLimiter,
): ContentManager {
  const internalOptions = { ...options };
  sharedUploadLimiters.set(internalOptions, limiter);
  try {
    return new ContentManager(internalOptions);
  } finally {
    sharedUploadLimiters.delete(internalOptions);
  }
}

function validateSnapshotMetadata(snapshot: { size: number | bigint; sha256: string }, metadata: ContentMetadata): void {
  if (metadata.size !== undefined && !sameInteger(metadata.size, snapshot.size))
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
  private readonly uploadLimiter: UploadLimiter;
  // Per-invocation receiver identity: pending/failed promises or confirmed receipt
  // metadata only. Immutable bytes remain exclusively in the attachment owner.
  private readonly receipts = new Map<object, Map<Attachment, Promise<ContentUploadReceipt>>>();
  private planningFinished = false;

  /** @internal Subsequent projections may consume only preplanned receipts. */
  finishPlanning(): void { this.planningFinished = true; }

  /** @internal Existing selected attachment references may reorder, never create bytes. */
  restoreAttachment(part: any, original: any, selected: any): any {
    if (part?.kind !== "attachment" || attachmentOwner(part.body) || part.body === undefined) return part;
    const visible = localParts(selected).find(({ part: candidate }) => candidate?.kind === "attachment" && candidate.id === part.id)?.part;
    const local = localParts(original).find(({ part: candidate }) => candidate?.kind === "attachment" && candidate.id === part.id)?.part;
    const owner = attachmentOwner(local?.body);
    if (!owner || visible?.selection !== "body" || typeof visible.body?.ref !== "string" ||
        part.body?.ref !== visible.body.ref || part.mediaType !== visible.mediaType || part.category !== visible.category)
      throw new Error("Effects cannot create or substitute binary attachment content");
    return { ...part, body: owner };
  }


  /** @internal Detach returned owners; dispose everything else in close(). */
  transfer(content: AttachmentContent): void { content.detachFrom(this.attachments); }

  constructor(options: ContentManagerOptions = {}) {
    const limit = options.maxSnapshotBytes ?? 64 * 1024 * 1024;
    this.budget = { used: 0, limit };
    if (!Number.isSafeInteger(limit) || limit < 0)
      throw new Error("Invalid snapshot byte limit");
    this.allowLoopback = options.allowLoopback ?? false;
    this.uploadLimiter = sharedUploadLimiters.get(options) ?? new UploadLimiter(options.maxConcurrentUploads);
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
      const owner = attachmentOwner(value);
      if (owner) {
        try { ownerAccess.claim(owner, this.ownership, this.budget); }
        catch { conflict = true; return; }
        this.hasAttachments = true;
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
   * A waiter can cancel its own read without retiring another consumer's source.
   */
  async readBody(
    body: Attachment,
    signal?: AbortSignal,
    metadata: ContentMetadata = {},
  ): Promise<Uint8Array> {
    this.lifetime.signal.throwIfAborted();
    this.own(body);
    signal?.throwIfAborted();
    const owner = attachmentOwner(body);
    if (!owner)
      throw new Error(
        "Content body must be an Attachment",
      );
    const controller = new AbortController();
    const abort = () =>
      controller.abort(signal?.reason ?? this.lifetime.signal.reason);
    signal?.addEventListener("abort", abort, { once: true });
    this.lifetime.signal.addEventListener("abort", abort, { once: true });
    if (signal?.aborted || this.lifetime.signal.aborted) abort();
    try {
      const snapshot = await abortable(
        this.snapshot(owner, controller.signal),
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
    receiver: object = {},
  ): Promise<any> {
    this.lifetime.signal.throwIfAborted();
    this.own(localParts(event).map(({ part }) => part?.body));
    signal?.throwIfAborted();
    const visit = async (
      value: any,
      path: Array<string | number> = [],
    ): Promise<any> => {
      if (value === null || typeof value !== "object") return value;
      if (
        isPartPath(event?.type, path) &&
        typeof value.id === "string" &&
        typeof value.kind === "string" &&
        typeof value.mediaType === "string"
      ) {
        const owner = attachmentOwner(value.body);
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
          if (key !== "body" && key !== "text" && key !== "gap" && key !== "selection")
            result[key] = child;
        }
        result.selection = mode;
        if (mode !== "body") return result;
        if (value.kind === "text" && typeof value.text === "string") {
          result.text = value.text;
          return result;
        }
        if (value.gap !== undefined && value.body === undefined) {
          result.gap = await visit(value.gap, [...path, "gap"]);
          return result;
        }
        if (!owner)
          throw new Error(
            "Body selection requires an Attachment, not a receiver reference",
          );
        if (!upload)
          throw new Error("Body selection requires upload configuration");
        this.validateUpload(upload);
        let scope = this.receipts.get(receiver);
        if (!scope) { scope = new Map(); this.receipts.set(receiver, scope); }
        let receipt = scope.get(owner);
        if (!receipt) {
          if (this.planningFinished) throw new Error("Attachment was not selected for this receiver");
          receipt = this.uploadOwner(owner, upload, send, value, signal);
          scope.set(owner, receipt);
        }
        const confirmed = await receipt;
        validateSnapshotMetadata(confirmed, value);
        delete result.size;
        delete result.sha256;
        result.body = { ref: confirmed.ref };
        return result;
      }
      return value;
    };
    const settled = await Promise.allSettled(localParts(event).map(async ({ part, path }) => ({
      path, part: await visit(part, path),
    })));
    const prepared = settled.map(result => {
      if (result.status === "rejected") throw result.reason;
      return result.value;
    });
    const byPath = new Map(prepared.map(({ part, path }) => [JSON.stringify(path), part]));
    return mapParts(event, (part, path) => byPath.get(JSON.stringify(path)) ?? part);
  }

  private async uploadOwner(owner: Attachment, upload: ContentUpload, send: ContentUploadRequest, metadata: ContentMetadata, signal?: AbortSignal): Promise<ContentUploadReceipt> {
    const controller = new AbortController();
    const abort = () =>
      controller.abort(signal?.reason ?? this.lifetime.signal.reason);
    signal?.addEventListener("abort", abort, { once: true });
    this.lifetime.signal.addEventListener("abort", abort, { once: true });
    if (signal?.aborted || this.lifetime.signal.aborted) abort();
    let release: (() => void) | undefined;
    const timeout = setTimeout(
      () =>
        controller.abort(
          new DOMException("Content upload timed out", "TimeoutError"),
        ),
      runtimeInteger(upload.timeoutMs, 1),
    );
    try {
      release = await this.uploadLimiter.acquire(controller.signal);
      const snapshot = await abortable(
        ownerAccess.snapshot(owner, controller.signal),
        controller.signal,
      );
      validateSnapshotMetadata(snapshot, metadata);
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
      if (!parsed.ok) throw new Error("Invalid or mismatched upload reference: invalid JSON");
      if (
        !sameInteger(parsed.value.size, snapshot.size) ||
        parsed.value.sha256 !== snapshot.sha256
      ) {
        throw new Error("Invalid or mismatched upload reference");
      }
      return parsed.value;
    } finally {
      release?.();
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      this.lifetime.signal.removeEventListener("abort", abort);
    }
  }

  /** @internal A protocol correlation lease shares the same owner, never bytes. */
  async retainBody(body: Attachment, signal: AbortSignal): Promise<{
    owner: Attachment; size: number; release: () => Promise<void>;
  }> {
    const owner = body;
    const snapshot = await ownerAccess.snapshot(owner, signal);
    return { owner, size: snapshot.size, release: ownerAccess.retain(owner) };
  }

  /** @internal Invocation-scoped borrow of an active protocol exchange. */
  lease(owner: Attachment): () => Promise<void> { return ownerAccess.retain(owner); }

  /** Cancel and dispose remaining owners. No backing bytes live here. */
  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.lifetime.abort(new Error("Content manager closed"));
    this.closePromise = Promise.all([...this.attachments].map(owner => owner.close())).then(() => {});
    this.attachments.clear();
    this.receipts.clear();
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
    runtimeInteger(upload.maxBytes);
    runtimeInteger(upload.timeoutMs, 1);
  }

  private snapshot(owner: Attachment, signal: AbortSignal): Promise<Snapshot> {
    return ownerAccess.snapshot(owner, signal);
  }
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
    // The generated receipt decoder parses integer tokens losslessly.
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
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
