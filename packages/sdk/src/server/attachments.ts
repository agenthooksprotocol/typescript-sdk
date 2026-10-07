import { createHash } from "node:crypto";
import {
  parseContentReference,
  type ContentReference,
} from "../draft/generated.js";
import { validateWire } from "../client/validation.js";

/** Safe protocol upload failure; applications can map status to an HTTP response. */
export class UploadError extends Error {
  readonly status = 400;
  constructor(message: string) {
    super(message);
    this.name = "UploadError";
  }
}
export interface Upload {
  /** Consume to successful EOF before committing storage or confirming availability. */
  body: ReadableStream<Uint8Array>;
  /** Declared framing, not independently verified until body reaches successful EOF. */
  size: number;
  sha256: string;
}

/** Synchronous framing checks; bytes are read and verified only on consumer demand.
 * The application owns authorization, storage, reference allocation and commit.
 * A storage writer must propagate stream errors and await successful EOF.
 */
function parse(request: Request): Upload {
  const length = request.headers.get("content-length");
  const sha256 = request.headers.get("ahp-content-sha256");
  if (
    request.method !== "POST" ||
    request.headers.get("content-type")?.toLowerCase() !==
      "application/octet-stream" ||
    request.headers.has("content-encoding") ||
    request.headers.has("transfer-encoding") ||
    length === null ||
    !/^[0-9]+$/.test(length) ||
    !Number.isSafeInteger(Number(length)) ||
    sha256 === null ||
    !/^[0-9a-f]{64}$/.test(sha256) ||
    request.bodyUsed ||
    request.body?.locked
  ) {
    throw new UploadError("Invalid upload framing");
  }
  const size = Number(length);
  const hash = createHash("sha256");
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let count = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        try {
          reader ??= request.body?.getReader();
          const chunk = reader
            ? await reader.read()
            : { done: true as const, value: undefined };
          if (chunk.done) {
            reader?.releaseLock();
            if (count !== size) throw new UploadError("Upload length mismatch");
            if (hash.digest("hex") !== sha256)
              throw new UploadError("Upload hash mismatch");
            controller.close();
            return;
          }
          if (
            !(chunk.value instanceof Uint8Array) ||
            chunk.value.byteLength > size - count
          )
            throw new UploadError("Upload length mismatch");
          // Snapshot mutable producer buffers before hashing and handing them to storage.
          const bytes = new Uint8Array(chunk.value);
          count += bytes.byteLength;
          hash.update(bytes);
          controller.enqueue(bytes);
        } catch (cause) {
          controller.error(
            cause instanceof UploadError
              ? cause
              : new UploadError("Upload body read failed"),
          );
          try {
            await reader?.cancel();
          } catch {
            /* Do not mask the validation failure. */
          }
          try {
            reader?.releaseLock();
          } catch {
            /* Reader may already have released its lock. */
          }
        }
      },
      async cancel(reason) {
        if (reader) {
          try {
            await reader.cancel(reason);
          } finally {
            reader.releaseLock();
          }
        } else {
          await request.body?.cancel(reason);
        }
      },
    },
    { highWaterMark: 0 },
  );
  return { body, size, sha256 };
}

/** Validate and format a descriptor. This does not verify bytes or commit storage.
 * Call only after an authorized storage write consumed body to successful EOF
 * and the immutable reference is synchronously available to the receiver.
 */
function response(descriptor: ContentReference): Response {
  if (validateWire("content-reference", descriptor).length !== 0)
    throw new UploadError("Invalid content descriptor");
  const decoded = parseContentReference(descriptor);
  if (!decoded.ok || !Number.isSafeInteger(decoded.value.size))
    throw new UploadError("Invalid content descriptor");
  return new Response(JSON.stringify(decoded.value), {
    status: 201,
    headers: { "content-type": "application/json" },
  });
}

export const attachments = { parse, response };
