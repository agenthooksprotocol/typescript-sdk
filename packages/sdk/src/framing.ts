import { HookOperationalError } from "./errors.js";

const MAX_LINE_BYTES = 1024 * 1024;

/** Incremental, strict UTF-8 NDJSON decoder. Empty lines are not frames. */
export class NdjsonDecoder {
  #buffer: Uint8Array = new Uint8Array(0);
  readonly #decoder = new TextDecoder("utf-8", { fatal: true });

  push(chunk: Uint8Array): string[] {
    const joined = new Uint8Array(this.#buffer.length + chunk.length);
    joined.set(this.#buffer);
    joined.set(chunk, this.#buffer.length);
    this.#buffer = joined;
    if (this.#buffer.length > MAX_LINE_BYTES && !this.#buffer.includes(0x0a)) {
      throw new HookOperationalError(
        "MALFORMED_JSON_RPC",
        "NDJSON frame exceeds 1 MiB",
      );
    }
    const lines: string[] = [];
    let newline: number;
    while ((newline = this.#buffer.indexOf(0x0a)) !== -1) {
      let frame = this.#buffer.subarray(0, newline);
      this.#buffer = this.#buffer.subarray(newline + 1);
      if (frame.length > MAX_LINE_BYTES)
        throw new HookOperationalError(
          "MALFORMED_JSON_RPC",
          "NDJSON frame exceeds 1 MiB",
        );
      if (frame.at(-1) === 0x0d) frame = frame.subarray(0, -1);
      if (frame.length === 0) {
        throw new HookOperationalError(
          "MALFORMED_JSON_RPC",
          "Empty NDJSON frame",
        );
      }
      try {
        lines.push(this.#decoder.decode(frame));
      } catch (error) {
        throw new HookOperationalError(
          "MALFORMED_UTF8",
          "NDJSON frame is not valid UTF-8",
          { cause: error },
        );
      }
    }
    return lines;
  }

  end(): void {
    if (this.#buffer.length !== 0) {
      throw new HookOperationalError(
        "MALFORMED_JSON_RPC",
        "Output ended with an incomplete NDJSON frame",
      );
    }
  }
}
