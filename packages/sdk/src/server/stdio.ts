import { stdin, stdout } from "node:process";
import { Writable, type Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

export interface StdioOptions {
  stdin?: Readable;
  stdout?: Writable;
  signal?: AbortSignal;
}

/** Serve UTF-8 NDJSON using an ordinary Web Request/Response handler.
 * Requests run sequentially. Nonempty bodies are written regardless of status;
 * physical CR/LF in response bodies becomes spaces to preserve line framing.
 * Resolves at EOF after flushing output, without ending stdout. The streams are
 * dedicated to this serving session: failure or abort destroys them. Handlers
 * doing long-running work should honor request.signal. No process is exited.
 */
export async function serveStdio(
  handler: (request: Request) => Response | Promise<Response>,
  options: StdioOptions = {},
): Promise<void> {
  const output = options.stdout ?? stdout;
  // A private sink waits for each write callback without ending caller stdout.
  const sink = new Writable({
    highWaterMark: 1,
    write(chunk, _encoding, callback) {
      output.write(chunk, callback);
    },
  });
  const outputError = (error: Error) => sink.destroy(error);
  const outputClosed = () => sink.destroy(new Error("Stdio output closed"));
  output.on("error", outputError);
  output.on("close", outputClosed);
  try {
    await pipeline(
      options.stdin ?? stdin,
      async function* (source, { signal }) {
        const decoder = new TextDecoder();
        let pending = "";
        const respond = async (body: string) => {
          const response = await handler(
            new Request("http://localhost/", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body,
              signal,
            }),
          );
          const text = await response.text();
          return text === "" ? "" : text.replace(/[\r\n]/g, " ") + "\n";
        };
        for await (const chunk of source) {
          pending +=
            typeof chunk === "string"
              ? decoder.decode() + chunk
              : decoder.decode(chunk, { stream: true });
          let newline: number;
          while ((newline = pending.indexOf("\n")) !== -1) {
            const line = pending.slice(0, newline);
            pending = pending.slice(newline + 1);
            const reply = await respond(line);
            if (reply !== "") yield reply;
          }
        }
        pending += decoder.decode();
        if (pending !== "") {
          const reply = await respond(pending);
          if (reply !== "") yield reply;
        }
      },
      sink,
      options.signal ? { signal: options.signal } : {},
    );
  } catch (error) {
    output.destroy();
    throw error;
  } finally {
    output.removeListener("error", outputError);
    output.removeListener("close", outputClosed);
  }
}
