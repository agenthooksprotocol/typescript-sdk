/** Test backend barriers are out-of-band controls, never cancellation RPCs. */
import { createServer } from "node:http";
import process from "node:process";
import { createInterface } from "node:readline";
import {
  hooks,
  type Message,
} from "agenthooksprotocol/server";
import type { ToolBeforeEffect } from "agenthooksprotocol/client";

export function barrier() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
export interface Script {
  effects: ToolBeforeEffect[];
  /** Raw bytes are reserved for deliberately invalid backend responses. */
  raw?: string | undefined;
  received: ReturnType<typeof barrier>;
  released: ReturnType<typeof barrier>;
  replied: ReturnType<typeof barrier>;
}
export async function openBackend() {
  const scripts = new Map<string, Script>();
  const requests: Message[] = [];
  const server = createServer(async (req: any, res: any) => {
    req.on("error", () => {});
    res.on("error", () => {});
    try {
      if (req.method !== "POST" || req.url !== "/hooks")
        throw new Error("Invalid route");
      let body = "";
      const utf8 = new TextDecoder("utf-8", { fatal: true });
      for await (const chunk of req) {
        body += utf8.decode(chunk, { stream: true });
        if (body.length > 1024 * 1024) throw new Error("Request too large");
      }
      body += utf8.decode();
      const request = new Request("http://localhost/hooks", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      const decoded = JSON.parse(body);
      const script = scripts.get(decoded.id);
      if (!script) throw new Error("Missing script");
      const response = await hooks.handle(request, async (message) => {
        if (message.method !== "hooks/intercept")
          throw new Error("Unexpected method");
        requests.push(message);
        script.received.resolve();
        await script.released.promise;
        return { effects: script.effects };
      });
      // Negative tests alone bypass the public server's response validation.
      res.writeHead(response.status, { "content-type": "application/json" });
      res.end(script.raw ?? (await response.text()));
      script.replied.resolve();
    } catch {
      res.statusCode = 500;
      res.end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}/hooks`;
  return {
    url,
    requests,
    configure(id: string, effects: ToolBeforeEffect[], raw?: string): Script {
      if (scripts.has(id)) throw new Error("Duplicate script");
      const script = {
        effects,
        raw,
        received: barrier(),
        released: barrier(),
        replied: barrier(),
      };
      scripts.set(id, script);
      return script;
    },
    async close() {
      for (const script of scripts.values()) script.released.resolve();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(resolve));
    },
  };
}

// The SDK owns this persistent stdio process. The relay gives its backend the
// same deterministic, out-of-band barriers as HTTP, including across respawns.
if (process.argv[2] === "--stdio") {
  const lines = createInterface({ input: process.stdin });
  for await (const body of lines) {
    const response = await fetch(process.argv[3]!, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    const responseBody = await response.text();
    if (responseBody !== "") process.stdout.write(responseBody + "\n");
  }
}
