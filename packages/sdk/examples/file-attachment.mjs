// Run: node packages/sdk/examples/file-attachment.mjs ./hooks.json ./document.bin
import { readFile, open } from 'node:fs/promises';
import { Attachment, Hooks } from 'agenthooksprotocol/client';

const [configPath, documentPath] = process.argv.slice(2);
if (!configPath || !documentPath) throw Error('Expected hooks.json and binary document paths');
const hooks = new Hooks(JSON.parse(await readFile(configPath, 'utf8')), {
  source: 'urn:example:document-agent',
  maxContentBytes: 4 * 1024 * 1024,
  capabilities: { 'turn.start': { modes: ['intercept'], capabilities: { effects: ['deny'] } } },
});
let result;
try {
  // No file descriptor is opened until a selected consumer or result reader asks.
  const document = Attachment.lazy(async signal => {
    signal.throwIfAborted();
    const file = await open(documentPath, 'r');
    try {
      if ((await file.stat()).size > 4 * 1024 * 1024) throw Error('Document too large');
      return await file.readFile({ signal });
    } finally { await file.close(); }
  });
  result = await hooks.turnStart({
    turn: { id: "turn-1" }, trigger: "user",
    items: [{ role: "user", parts: [
      { kind: "text", text: "Inspect this document." },
      { id: "document", kind: "attachment", mediaType: "application/octet-stream", body: document },
    ] }],
  });
  await hooks.close();
  if (result.interrupted || result.permission === 'deny') throw Error('Turn not permitted');
  // Local effective content remains readable after transport shutdown.
  console.log(await result.content.read('document'));
} finally {
  try { await result?.content?.close(); }
  finally { await hooks.close(); }
}
